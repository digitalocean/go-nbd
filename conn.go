// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

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

const (
	DefaultPort       = 10809
	DefaultBufferSize = 5 * 1024
)

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
	NetDialer *net.Dialer
	Buffer    []byte
}

func (d *Dialer) Dial(ctx context.Context, uri *URI) (conn *Conn, err error) {
	if d.NetDialer == nil {
		d.NetDialer = new(net.Dialer)
	}
	if len(d.Buffer) == 0 {
		d.Buffer = make([]byte, DefaultBufferSize)
	}

	buflk := make(chan struct{}, 1)
	buflk <- struct{}{}

	conn = &Conn{
		fixed:         false,
		discardZeroes: true,
		buflk:         buflk,
		buf:           d.Buffer,
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

	transport, err := d.NetDialer.DialContext(ctx, network, address)
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

	buflk chan struct{}
	buf   []byte
}

func (c *Conn) Connect() (err error) {
	if state := c.state(); state != connectionStateNew {
		return errors.New("duplicate call to connect")
	}
	defer func() {
		if err != nil {
			c.setState(connectionStateError)
		}
	}()

	var hello nbdproto.NegotiationHeader
	err = binary.Read(c.conn, binary.BigEndian, &hello)
	if err != nil {
		return fmt.Errorf("read first header: %w", err)
	}
	if hello.Magic != nbdproto.NBD_MAGIC {
		return fmt.Errorf("expected NBD_MAGIC, got %x", hello.Magic)
	}
	if hello.Version == nbdproto.CLI_SERV {
		return fmt.Errorf("negotiation: server offered unsupported oldstyle negotiation")
	}
	if hello.Version != nbdproto.HAVE_OPT {
		return fmt.Errorf("negotiation: expected IHAVEOPT, got %x", hello.Version)
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

func (c *Conn) ExportName(name string) (size uint64, flags nbdproto.TransmissionFlags, err error) {
	if state := c.state(); state != connectionStateOptions {
		return 0, 0, errNotOption
	}

	err = requestOption(c.conn, &exportNameRequest{export: name})
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

func (c *Conn) Abort() error {
	if c.inTransmission.Load() {
		return nil
	}
	return requestOption(c.conn, &abortRequest{})
}

func (c *Conn) List() (exports []string, err error) {
	if state := c.state(); state != connectionStateOptions {
		return nil, errNotOption
	}

	acquire(c.buflk)
	defer release(c.buflk)
	buf := c.buf

	err = requestOption(c.conn, &listExportsRequest{})
	if err != nil {
		return nil, err
	}

	for {
		reply, err := readOptionReply(c.conn, buf)
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

// StartTLS upgrades the connection to TLS. Config must set either ServerName or InsecureSkipVerify.
func (c *Conn) StartTLS(config *tls.Config) error {
	if state := c.state(); state != connectionStateOptions {
		return errNotOption
	}

	acquire(c.buflk)
	defer release(c.buflk)
	buf := c.buf

	err := requestOption(c.conn, &startTLSRequest{})
	if err != nil {
		return err
	}

	reply, err := readOptionReply(c.conn, buf)
	if err != nil {
		return err
	}

	if reply.Type != nbdproto.REP_ACK {
		return errors.New("server did not reply with error or ACK")
	}

	c.conn = tls.Client(c.conn, config)
	return nil
}

func (c *Conn) Read(buf []byte, offset uint64, flags CommandFlags) (n int, err error) {
	if state := c.state(); state != connectionStateTransmission {
		return 0, errNotTransmission
	}

	acquire(c.buflk)
	defer release(c.buflk)
	intbuf := c.buf

	cookie := c.cookie.Add(1)

	err = requestTransmit(c.conn, uint16(flags), nbdproto.CMD_READ, cookie, offset, uint32(len(buf)), nil)
	if err != nil {
		return 0, err
	}

	for {
		var hdr transmissionHeader
		err = hdr.DecodeFrom(c.conn)
		if err != nil {
			return n, err
		}

		if hdr.simple == nil && hdr.structured == nil {
			return n, errors.New("invalid enum state for transmissionHeader")
		}

		cookieMismatch := errors.New("cookie mismatch")

		if hdr.simple != nil && hdr.simple.Cookie != cookie {
			return n, cookieMismatch
		}
		if hdr.structured != nil && hdr.structured.Cookie != cookie {
			return n, cookieMismatch
		}

		if hdr.IsErr() {
			var terr TransmissionError
			d := transmissionErrorDecoder{hdr: hdr, buf: intbuf, r: c.conn}
			if err := d.Decode(&terr); err != nil {
				return n, err
			}
			return n, &terr
		}

		if hdr.simple != nil {
			_, err := io.ReadFull(c.conn, buf)
			if err != nil {
				return n, fmt.Errorf("read data from simple chunk: %w", err)
			}
			return n, nil
		}

		switch hdr.structured.Type {
		case nbdproto.REPLY_TYPE_NONE:
			if hdr.structured.Flags&nbdproto.REPLY_FLAG_DONE != 0 {
				return n, errors.New("server sent NBD_REP_TYPE_NONE without REPLY_FLAG_DONE")
			}
			return n, nil
		case nbdproto.REPLY_TYPE_OFFSET_HOLE:
			var hole readHole
			if err := binary.Read(c.conn, binary.BigEndian, &hole); err != nil {
				return n, fmt.Errorf("read hole offset from chunk: %w", err)
			}
			n += int(hole.Length)
		case nbdproto.REPLY_TYPE_OFFSET_DATA:
			var absoluteOffset uint64
			if err := binary.Read(c.conn, binary.BigEndian, &absoluteOffset); err != nil {
				return n, fmt.Errorf("read data offset from chunk: %w", err)
			}

			normalizedOffset := absoluteOffset - offset
			datalen := int(hdr.structured.Length) - int(unsafe.Sizeof(absoluteOffset))

			if int(normalizedOffset)+int(datalen) > len(buf) {
				return n, errors.New("server chunk is too large for given buf")
			}

			written, err := io.ReadFull(c.conn, buf[normalizedOffset:])
			n += written
			if err != nil {
				return n, fmt.Errorf("read chunk into buf: %w", err)
			}
		default:
			return n, fmt.Errorf("unexpected REP_TYPE %d", hdr.structured.Type)
		}

		if hdr.structured.Flags&nbdproto.REPLY_FLAG_DONE != 0 {
			return n, nil
		}
	}
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func acquire(lock chan struct{}) {
	<-lock
}

func release(lock chan struct{}) {
	lock <- struct{}{}
}
