// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

type connectionState int

const (
	connectionStateInvalid connectionState = iota
	connectionStateNew
	connectionStateOptions
	connectionStateTransmission
	connectionStateClosed
	connectionStateError
)

const DefaultPort = 10809

var schemes = []string{"nbd", "nbds", "nbd+unix", "nbds+unix"}

var (
	errNotOption       = errors.New("not in option phase")
	errNotTransmission = errors.New("not in transmission phase")
)

type URI struct {
	*url.URL
}

func MustURI(s string) *URI {
	u, err := ParseURI(s)
	if err != nil {
		panic(err)
	}
	return u
}

func ParseURI(s string) (*URI, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse nbd uri: %v", err)
	}

	if !slices.Contains(schemes, u.Scheme) {
		return nil, fmt.Errorf("nbd uri scheme is not one of %v", schemes)
	}

	return &URI{URL: u}, nil
}

type Dialer struct {
	// Pass in a net.Dialer to configure settings. Pass in nil
	// or zero-value to use defaults.
	NetDialer *net.Dialer

	// Pass in a TLS config if using NBD over TLS. Pass in nil
	// or zero-value to use defaults.
	TLSConfig *tls.Config
}

func (d *Dialer) Dial(ctx context.Context, uri *URI) (conn *Conn, err error) {
	if d.NetDialer == nil {
		d.NetDialer = new(net.Dialer)
	}

	conn = &Conn{
		fixed:         false,
		discardZeroes: true,
	}
	conn.setState(connectionStateNew)

	address := uri.Host
	network := "tcp"
	if strings.HasSuffix(uri.Scheme, "unix") {
		network = "unix"
		address = uri.Query().Get("socket")
	} else if p := uri.Port(); p == "" {
		address = net.JoinHostPort(address, strconv.Itoa(DefaultPort))
	}

	var transport net.Conn
	if strings.HasPrefix(uri.Scheme, "nbds") {
		tlsDialer := tls.Dialer{
			NetDialer: d.NetDialer,
			Config:    d.TLSConfig,
		}
		transport, err = tlsDialer.DialContext(ctx, network, address)
	} else {
		transport, err = d.NetDialer.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, fmt.Errorf("dial nbd: %w", err)
	}

	conn.conn = transport
	conn.export = uri.Path

	return conn, nil
}

type Conn struct {
	conn          net.Conn
	export        string
	fixed         bool
	discardZeroes bool
	structured    bool

	state_         atomic.Int32
	inTransmission atomic.Bool
	cookie         atomic.Uint64

	mu      sync.Mutex
	streams map[uint64]stream
	wg      *errgroup.Group
}

func (c *Conn) Connect(ctx context.Context) (err error) {
	work := make(chan error)
	go func() {
		defer close(work)
		work <- c.connect()
	}()
	select {
	case <-ctx.Done():
		_ = c.conn.SetDeadline(time.Now())
		<-work
		_ = c.conn.SetDeadline(time.Time{})
		return ctx.Err()
	case err := <-work:
		return err
	}
}

func (c *Conn) connect() (err error) {
	if state := c.state(); state != connectionStateNew {
		return errors.New("duplicate call to connect")
	}
	defer func() {
		if err == nil {
			return
		}
		c.setState(connectionStateError)
	}()
	var hello nbdproto.NegotiationHeader
	err = binary.Read(c.conn, binary.BigEndian, &hello)
	if err != nil {
		return fmt.Errorf("read first header: %w", err)
	}

	if hello.Magic != nbdproto.NBD_MAGIC {
		return fmt.Errorf("expected NBD_MAGIC, got %x",
			hello.Magic)
	}

	if hello.Version == nbdproto.CLI_SERV {
		return fmt.Errorf("negotiation: server offered unsupported oldstyle negotiation")
	}

	if hello.Version != nbdproto.HAVE_OPT {
		return fmt.Errorf("negotiation: expected IHAVEOPT, got %x",
			hello.Version)
	}

	var server uint16
	err = binary.Read(c.conn, binary.BigEndian, &server)
	if err != nil {
		return fmt.Errorf("negotiation: read server flags: %w", err)
	}

	if server&nbdproto.FLAG_FIXED_NEWSTYLE == 0 {
		return fmt.Errorf("negotiation: server did not set FLAG_FIXED_NEWSTYLE")
	}

	client := uint32(nbdproto.FLAG_FIXED_NEWSTYLE)

	if server&nbdproto.FLAG_NO_ZEROES != 0 {
		client |= uint32(nbdproto.FLAG_NO_ZEROES)
		c.discardZeroes = false
	}

	err = binary.Write(c.conn, binary.BigEndian, client)
	if err != nil {
		return fmt.Errorf("negotiation: send client flags: %w", err)
	}

	c.setState(connectionStateOptions)
	return nil
}

func (c *Conn) ExportName(ctx context.Context, name string) (size uint64, flags TransmissionFlags, err error) {
	work := func() error {
		size, flags, err = c.exportName(name)
		return err
	}
	err = c.optionCtx(ctx, work)
	return size, flags, err
}

func (c *Conn) exportName(name string) (size uint64, flags TransmissionFlags, err error) {
	if state := c.state(); state != connectionStateOptions {
		return 0, 0, errNotOption
	}
	err = requestOption(c.conn, &exportNameRequest{
		export: name,
	})
	if err != nil {
		return 0, 0, err
	}
	var reply repExportName
	err = binary.Read(c.conn, binary.BigEndian, &reply)
	if err != nil {
		return 0, 0, err
	}

	if c.discardZeroes {
		var zeroes [124]byte
		_, err := io.ReadFull(c.conn, zeroes[:])
		if err != nil {
			return 0, 0, err
		}
	}

	c.enterTransmission()
	return reply.ExportSize, reply.TransmissionFlags, nil
}

func (c *Conn) Abort(ctx context.Context) error {
	work := func() error {
		return c.abort()
	}
	return c.optionCtx(ctx, work)
}

func (c *Conn) abort() error {
	if c.inTransmission.Load() {
		return nil
	}
	err := requestOption(c.conn, &abortRequest{})
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) List(ctx context.Context) (exports []string, err error) {
	work := func() error {
		exports, err = c.list()
		return err
	}
	err = c.optionCtx(ctx, work)
	return exports, err
}

func (c *Conn) list() (exports []string, err error) {
	if state := c.state(); state != connectionStateOptions {
		return nil, errNotOption
	}

	err = requestOption(c.conn, &listExportsRequest{})
	if err != nil {
		return nil, err
	}

	for {
		reply, err := readOptionReply(c.conn)
		if err != nil {
			return nil, err
		}
		if reply.Type == nbdproto.REP_ACK {
			break
		}
		var r repServer
		err = r.UnmarshalNBDReply(reply.Payload)
		if err != nil {
			return nil, err
		}
		exports = append(exports, r.Name)
	}
	return exports, nil
}

func (c *Conn) Info(ctx context.Context, name string, requests []InfoRequest) (info ExportInfo, err error) {
	work := func() error {
		info, err = c.info(name, requests)
		return err
	}
	err = c.optionCtx(ctx, work)
	return info, err
}

func (c *Conn) info(name string, requests []InfoRequest) (ExportInfo, error) {
	if state := c.state(); state != connectionStateOptions {
		return ExportInfo{}, errNotOption
	}
	return infoGo(c.conn, &infoRequest{
		infoGoRequest: infoGoRequest{
			export:   name,
			requests: requests,
		},
	})
}

func (c *Conn) Go(ctx context.Context, name string, requests []InfoRequest) (info ExportInfo, err error) {
	work := func() error {
		info, err = c.go_(name, requests)
		return err
	}
	err = c.optionCtx(ctx, work)
	return info, err
}

func (c *Conn) go_(name string, requests []InfoRequest) (ExportInfo, error) {
	if state := c.state(); state != connectionStateOptions {
		return ExportInfo{}, errNotOption
	}
	info, err := infoGo(c.conn, &goRequest{
		infoGoRequest: infoGoRequest{
			export:   name,
			requests: requests,
		},
	})
	if err != nil {
		return info, err
	}
	c.enterTransmission()
	return info, nil
}

func infoGo[R interface {
	*infoRequest | *goRequest
	option
}](server io.ReadWriter, opt R) (ExportInfo, error) {
	err := requestOption(server, opt)
	if err != nil {
		return ExportInfo{}, err
	}

	var info ExportInfo

	for {
		reply, err := readOptionReply(server)
		if err != nil {
			return ExportInfo{}, err
		}
		if reply.Type == nbdproto.REP_ACK {
			break
		}
		var r repInfo
		err = r.UnmarshalNBDReply(reply.Payload)
		if err != nil {
			return ExportInfo{}, err
		}
		switch r.Type {
		case nbdproto.INFO_EXPORT:
			var i repInfoExport
			err = i.UnmarshalNBDReply(r.Payload)
			if err != nil {
				return ExportInfo{}, err
			}
			info.Size = i.Size
			info.TransmissionFlags = i.Flags
		case nbdproto.INFO_NAME:
			var i repInfoName
			err = i.UnmarshalNBDReply(r.Payload)
			if err != nil {
				return ExportInfo{}, err
			}
			info.Name = i.Name
		case nbdproto.INFO_DESCRIPTION:
			var i repInfoDescription
			err = i.UnmarshalNBDReply(r.Payload)
			if err != nil {
				return ExportInfo{}, err
			}
			info.Description = i.Description
		case nbdproto.INFO_BLOCK_SIZE:
			var i repInfoBlockSize
			err = i.UnmarshalNBDReply(r.Payload)
			if err != nil {
				return ExportInfo{}, err
			}
			info.MinBlockSize = i.MinimumBlockSize
			info.PreferredBlockSize = i.PreferredBlockSize
			info.MaxBlockSize = i.MaximumBlockSize
		}
	}

	return info, nil
}

func (c *Conn) StructuredReplies(ctx context.Context) error {
	work := func() error {
		return c.structuredReplies()
	}
	return c.optionCtx(ctx, work)
}

func (c *Conn) structuredReplies() error {
	if state := c.state(); state != connectionStateOptions {
		return errNotOption
	}
	err := requestOption(c.conn, &structuredRepliesRequest{})
	if err != nil {
		return err
	}
	reply, err := readOptionReply(c.conn)
	if err != nil {
		return err
	}
	var r ack
	err = r.UnmarshalNBDReply(reply.Payload)
	if err != nil {
		return err
	}
	c.structured = true
	return nil
}

func (c *Conn) ListMetaContext(ctx context.Context, export string, queries ...string) (metas []MetaContext, err error) {
	work := func() error {
		metas, err = c.listMetaContext(export, queries...)
		return err
	}
	err = c.optionCtx(ctx, work)
	return metas, err
}

func (c *Conn) listMetaContext(export string, queries ...string) ([]MetaContext, error) {
	if state := c.state(); state != connectionStateOptions {
		return nil, errNotOption
	}
	err := requestOption(c.conn, &listMetaContextsRequest{
		export:  export,
		queries: queries,
	})
	if err != nil {
		return nil, err
	}

	var exports []MetaContext

	for {
		reply, err := readOptionReply(c.conn)
		if err != nil {
			return nil, err
		}
		if reply.Type == nbdproto.REP_ACK {
			break
		}
		var r repMetaContext
		err = r.UnmarshalNBDReply(reply.Payload)
		if err != nil {
			return nil, err
		}
		exports = append(exports, MetaContext{Name: r.Name})
	}

	return exports, nil
}

func (c *Conn) SetMetaContext(ctx context.Context, export string, query string, additional ...string) (metas []MetaContext, err error) {
	work := func() error {
		metas, err = c.setMetaContext(export, query, additional...)
		return err
	}
	err = c.optionCtx(ctx, work)
	return metas, err
}

func (c *Conn) setMetaContext(export string, query string, additional ...string) ([]MetaContext, error) {
	if state := c.state(); state != connectionStateOptions {
		return nil, errNotOption
	}
	err := requestOption(c.conn, &setMetaContext{
		export:  export,
		queries: append([]string{query}, additional...),
	})
	if err != nil {
		return nil, err
	}

	var exports []MetaContext

	for {
		reply, err := readOptionReply(c.conn)
		if err != nil {
			return nil, err
		}
		if reply.Type == nbdproto.REP_ACK {
			break
		}
		var r repMetaContext
		err = r.UnmarshalNBDReply(reply.Payload)
		if err != nil {
			return nil, err
		}
		exports = append(exports, MetaContext{Name: r.Name})
	}

	return exports, nil
}

func (c *Conn) Read(ctx context.Context, flags CommandFlags, offset uint64, length uint32) ([]Read, error) {
	if state := c.state(); state != connectionStateTransmission {
		return nil, errNotTransmission
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, length)
	defer drain()

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_READ, cookie, offset, length, nil)
	if err != nil {
		return nil, err
	}

	var reads []Read

	for r := range stream {
		if r.err != nil {
			return nil, r.err
		}
		if r.simple != nil {
			reads = append(reads, Read{Data: &ReadData{Offset: offset, Data: r.buf}})
			return reads, nil
		} else if r.structured != nil {
			if r.structured.Type == nbdproto.REPLY_TYPE_OFFSET_DATA {
				var read ReadData
				if err := read.UnmarshalNBDReply(r.buf); err != nil {
					return nil, err
				}
				reads = append(reads, Read{Data: &read})
			} else if r.structured.Type == nbdproto.REPLY_TYPE_OFFSET_HOLE {
				var read ReadHole
				if err := read.UnmarshalNBDReply(r.buf); err != nil {
					return nil, err
				}
				reads = append(reads, Read{Hole: &read})
			}
		} else {
			return nil, fmt.Errorf("did not receive simple or structured reply")
		}
	}

	return reads, nil
}

func (c *Conn) Write(ctx context.Context, flags CommandFlags, offset uint64, data []byte) error {
	if state := c.state(); state != connectionStateTransmission {
		return errNotTransmission
	}

	if len(data) > math.MaxUint32 {
		return errors.New("payload size exceeds protocol limit")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, 0)
	defer drain()

	length := uint32(len(data))

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_WRITE, cookie, offset, length, data)
	if err != nil {
		return err
	}

	for r := range stream {
		if r.err != nil {
			return r.err
		}
	}

	return nil
}

func (c *Conn) Flush(ctx context.Context, flags CommandFlags) error {
	if state := c.state(); state != connectionStateTransmission {
		return errNotTransmission
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, 0)
	defer drain()

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_FLUSH, cookie, 0, 0, nil)
	if err != nil {
		return err
	}

	for r := range stream {
		if r.err != nil {
			return r.err
		}
	}

	return nil
}

func (c *Conn) Trim(ctx context.Context, flags CommandFlags, offset uint64, length uint32) error {
	if state := c.state(); state != connectionStateTransmission {
		return errNotTransmission
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, 0)
	defer drain()

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_TRIM, cookie, offset, length, nil)
	if err != nil {
		return err
	}

	for r := range stream {
		if r.err != nil {
			return r.err
		}
	}

	return nil
}

func (c *Conn) Cache(ctx context.Context, flags CommandFlags, offset uint64, length uint32) error {
	if state := c.state(); state != connectionStateTransmission {
		return errNotTransmission
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, 0)
	defer drain()

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_CACHE, cookie, offset, length, nil)
	if err != nil {
		return err
	}

	for r := range stream {
		if r.err != nil {
			return r.err
		}
	}

	return nil
}

func (c *Conn) WriteZeroes(ctx context.Context, flags CommandFlags, offset uint64, length uint32) error {
	if state := c.state(); state != connectionStateTransmission {
		return errNotTransmission
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, 0)
	defer drain()

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_WRITE_ZEROES, cookie, offset, length, nil)
	if err != nil {
		return err
	}

	for r := range stream {
		if r.err != nil {
			return r.err
		}
	}

	return nil
}

func (c *Conn) BlockStatus(ctx context.Context, flags CommandFlags, offset uint64, length uint32) (BlockStatus, error) {
	if state := c.state(); state != connectionStateTransmission {
		return BlockStatus{}, errNotTransmission
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cookie := c.cookie.Add(1)
	stream, drain := c.addStream(ctx, cookie, 0)
	defer drain()

	err := c.requestTransmit(ctx, uint16(flags), nbdproto.CMD_BLOCK_STATUS, cookie, offset, length, nil)
	if err != nil {
		return BlockStatus{}, err
	}

	var status BlockStatus

	for r := range stream {
		if r.err != nil {
			return BlockStatus{}, r.err
		}
		if r.structured == nil {
			return BlockStatus{}, errors.New("server did not send structured reply")
		}
		if err := status.UnmarshalNBDReply(r.buf); err != nil {
			return BlockStatus{}, err
		}
	}

	return status, nil
}

var deadlineStates = []connectionState{
	connectionStateNew,
	connectionStateOptions,
	connectionStateTransmission,
}

var errDeadlineImpossible = errors.New("connection state not one of: new, option, transmission")

// SetDeadline sets the Read and Write deadlines associated with the
// underlying connection. See Conn.SetReadDeadline for caveats
// on its use during the transmission phase.
//
// Otherwise, expect the same behavior as net.Conn.SetDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	if !slices.Contains(deadlineStates, c.state()) {
		return errDeadlineImpossible
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the Read deadline associated with the underlying
// connection.
//
// Note that if the NBD server exceeds the deadline set here during the
// transmission phase, the nbd.Conn will enter an error state and cannot
// be reused. The transmission phase is not strictly a serialized client-
// server-response-type situation, and this function does not apply a
// deadline to a specific request-response stream, but the entire underlying
// connection which contains an interleaving of messages to/from the NBD
// server.
//
// Otherwise, expect the same behavior as net.Conn.SetReadDeadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if !slices.Contains(deadlineStates, c.state()) {
		return errDeadlineImpossible
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the Write deadline associated with the underlying
// connection. Expect the same behavior as net.Conn.SetWriteDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if !slices.Contains(deadlineStates, c.state()) {
		return errDeadlineImpossible
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Disconnect(ctx context.Context) error {
	if state := c.state(); state == connectionStateError {
		return nil
	}
	if !c.inTransmission.Load() {
		return errNotTransmission
	}

	cookie := c.cookie.Add(1)
	err := c.requestTransmit(ctx, 0, nbdproto.CMD_DISC, cookie, 0, 0, nil)
	if err != nil {
		return err
	}

	c.setState(connectionStateClosed)
	return nil
}

func (c *Conn) state() connectionState {
	return connectionState(c.state_.Load())
}

func (c *Conn) setState(s connectionState) {
	c.state_.Store(int32(s))
}

func (c *Conn) enterTransmission() {
	if c.inTransmission.Load() {
		// FIXME: BUG?
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.streams = make(map[uint64]stream)
	c.wg = new(errgroup.Group)
	c.wg.Go(c.demuxReplies)
	c.inTransmission.Store(true)
	c.setState(connectionStateTransmission)
}

func (c *Conn) Close() error {
	if c.inTransmission.Load() {
		defer func() { _ = c.wg.Wait() }()
	}
	return c.conn.Close()
}
