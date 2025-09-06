// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"unsafe"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

// TransmissionFlags describe what capabilities the server has
// advertised for this connection.
type TransmissionFlags uint16

const (
	TransmissionFlagHasFlags           TransmissionFlags = 1 << 0
	TransmissionFlagReadOnly           TransmissionFlags = 1 << 1
	TransmissionFlagSendFlush          TransmissionFlags = 1 << 2
	TransmissionFlagSendFUA            TransmissionFlags = 1 << 3
	TransmissionFlagRotational         TransmissionFlags = 1 << 4
	TransmissionFlagTrim               TransmissionFlags = 1 << 5
	TransmissionFlagSendWriteZeroes    TransmissionFlags = 1 << 6
	TransmissionFlagSendDF             TransmissionFlags = 1 << 7
	TransmissionFlagCanMultiConn       TransmissionFlags = 1 << 8
	TransmissionFlagSendResize         TransmissionFlags = 1 << 9
	TransmissionFlagSendCache          TransmissionFlags = 1 << 10
	TransmissionFlagSendFastZero       TransmissionFlags = 1 << 11
	TransmissionFlagBlockStatusPayload TransmissionFlags = 1 << 12
)

// CommandFlags allow customizing transmission request behavior.
type CommandFlags uint16

const (
	CommandFlagFUA        CommandFlags = 1 << 0
	CommandFlagNoHole     CommandFlags = 1 << 1
	CommandFlagDF         CommandFlags = 1 << 2
	CommandFlagReqOne     CommandFlags = 1 << 3
	CommandFlagFastZero   CommandFlags = 1 << 4
	CommandFlagPayloadLen CommandFlags = 1 << 5
)

// ErrStreamClosing indicates the nbd client received data that it
// did not expect or otherwise know how to handle and is therefore
// abandoning the connection.
var ErrStreamClosing = errors.New("nbd stream closing")

// Read is an "enum-like" type. If Data is not nil, then it contains
// data from the corresponding Read call. If Hole is not nil, then
// that extent of the read is a hole. It is a bug if both are nil
// or both are non-nil, please report it.
type Read struct {
	Data *ReadData
	Hole *ReadHole
}

// ReadData contains data from a call to Read for a specified extent.
// The extent is [ReadData.Offset, len(ReadData.Data)).
type ReadData struct {
	Offset uint64
	Data   []byte
}

func (r *ReadData) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &r.Offset); err != nil {
		return fmt.Errorf("read offset: %w", err)
	}
	r.Data = buf.Bytes()
	return nil
}

// ReadHole indicates this extent is a hole.
type ReadHole struct {
	Offset uint64
	Length uint32
}

func (r *ReadHole) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.BigEndian, &r.Offset); err != nil {
		return fmt.Errorf("read offset: %w", err)
	}
	if err := binary.Read(buf, binary.BigEndian, &r.Length); err != nil {
		return fmt.Errorf("read length: %w", err)
	}
	return nil
}

// BlockStatus describes the given meta context. See package "nbdmeta"
// for helper types to interpret the BlockStatusDescriptors' status flags.
type BlockStatus struct {
	ID          uint32
	Descriptors []BlockStatusDescriptor
}

func (b *BlockStatus) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.BigEndian, &b.ID); err != nil {
		return fmt.Errorf("block status metadata ID: %w", err)
	}
	for {
		var bd BlockStatusDescriptor
		err := binary.Read(buf, binary.BigEndian, &bd.Length)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("block status: read length: %w", err)
		}
		err = binary.Read(buf, binary.BigEndian, &bd.Status)
		if err != nil {
			return fmt.Errorf("block status: read status: %w", err)
		}
		b.Descriptors = append(b.Descriptors, bd)
	}
	return nil
}

// BlockStatusDescriptor describes a run of blocks, depending
// on the meta context. See package nbdmeta for types that
// help interpret the Status field.
type BlockStatusDescriptor struct {
	Length uint32
	Status uint32
}

type reply struct {
	simple     *nbdproto.SimpleReplyHeader
	structured *nbdproto.StructuredReplyHeader
	buf        []byte
	err        error
}

type stream struct {
	replies chan reply
	length  uint32
}

func (c *Conn) addStream(cookie uint64, length uint32) (replies chan reply, drain func()) {
	replies = make(chan reply, 1)
	drain = func() {
		for range replies {
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.streams[cookie] = stream{
		replies: replies,
		length:  length,
	}

	return replies, drain
}

func (c *Conn) demuxReplies() (err error) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, stream := range c.streams {
			stream.replies <- reply{err: errors.Join(ErrStreamClosing, err)}
			close(stream.replies)
		}
		c.streams = nil
		c.setState(connectionStateError)
	}()

	for {
		var magic uint32
		if err := binary.Read(c.conn, binary.BigEndian, &magic); err != nil {
			return fmt.Errorf("route replies: read magic: %w", err)
		}
		if magic != nbdproto.NBD_SIMPLE_REPLY_MAGIC && magic != nbdproto.NBD_STRUCTURED_REPLY_MAGIC {
			return fmt.Errorf("route replies: got invalid magic %x", magic)
		}
		if magic == nbdproto.NBD_SIMPLE_REPLY_MAGIC {
			hdr := nbdproto.SimpleReplyHeader{
				Magic: magic,
			}
			if err := binary.Read(c.conn, binary.BigEndian, &hdr.Error); err != nil {
				return fmt.Errorf("route replies: simple: read error: %w", err)
			}
			if err := binary.Read(c.conn, binary.BigEndian, &hdr.Cookie); err != nil {
				return fmt.Errorf("route replies: simple: read cookie: %w", err)
			}

			var length uint32
			func() {
				// Avoid reading the expected length from the request
				// if this is a simple error. This will leave length
				// above to 0 so that we read 0 bytes below.
				if hdr.Error != 0 {
					return
				}
				c.mu.Lock()
				defer c.mu.Unlock()
				stream, ok := c.streams[hdr.Cookie]
				if !ok {
					return
				}
				length = stream.length
			}()

			buf := make([]byte, length)
			if _, err := io.ReadFull(c.conn, buf); err != nil {
				return fmt.Errorf("route replies: simple: read payload: %w", err)
			}

			func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				stream, ok := c.streams[hdr.Cookie]
				if !ok {
					return
				}
				var err error
				if hdr.Error != 0 {
					err = &TransmissionError{Code: TransmissionErrorCode(hdr.Error)}
				}
				r := reply{
					simple: &hdr,
					buf:    buf,
					err:    err,
				}
				stream.replies <- r
				close(stream.replies)
				delete(c.streams, hdr.Cookie)
			}()
			continue
		}

		hdr := nbdproto.StructuredReplyHeader{
			Magic: nbdproto.NBD_STRUCTURED_REPLY_MAGIC,
		}
		if err := binary.Read(c.conn, binary.BigEndian, &hdr.Flags); err != nil {
			return fmt.Errorf("route replies: structured: read flags: %w", err)
		}
		if err := binary.Read(c.conn, binary.BigEndian, &hdr.Type); err != nil {
			return fmt.Errorf("route replies: structured: read type: %w", err)
		}
		if err := binary.Read(c.conn, binary.BigEndian, &hdr.Cookie); err != nil {
			return fmt.Errorf("route replies: structured: read cookie: %w", err)
		}
		if err := binary.Read(c.conn, binary.BigEndian, &hdr.Length); err != nil {
			return fmt.Errorf("route replies: structured: read length: %w", err)
		}
		buf := make([]byte, hdr.Length)
		if _, err := io.ReadFull(c.conn, buf); err != nil {
			return fmt.Errorf("route replies: structured: read payload: %w", err)
		}
		var replyError error
		if isTXError(hdr.Type) {
			b := bytes.NewBuffer(buf)
			var code uint32
			if err := binary.Read(b, binary.BigEndian, &code); err != nil {
				return fmt.Errorf("route replies: structured: read error code: %w", err)
			}
			var length uint16
			if err := binary.Read(b, binary.BigEndian, &length); err != nil {
				return fmt.Errorf("route replies: structured: read message length: %w", err)
			}
			var offset uint64
			if hdr.Type == nbdproto.REPLY_TYPE_ERROR_OFFSET {
				if err := binary.Read(b, binary.BigEndian, &offset); err != nil {
					return fmt.Errorf("route replies: structured: read offset: %w", err)
				}
			}
			m := b.String()
			replyError = &TransmissionError{
				Code: TransmissionErrorCode(code),
				Message: NullErrorMessage{
					Value: m,
					Valid: len(m) > 0,
				},
				Offset: NullOffset{
					Value: offset,
					Valid: hdr.Type == nbdproto.REPLY_TYPE_ERROR_OFFSET,
				},
			}
		}
		func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			stream, ok := c.streams[hdr.Cookie]
			if !ok {
				return
			}
			r := reply{
				structured: &hdr,
				buf:        buf,
				err:        replyError,
			}
			if replyError != nil {
				r.buf = nil
			}
			stream.replies <- r
			if hdr.Flags&nbdproto.REPLY_FLAG_DONE == 0 {
				return
			}
			close(stream.replies)
			delete(c.streams, hdr.Cookie)
		}()
	}
}

func requestTransmit(server io.Writer, cflags uint16, ty uint16, cookie uint64, offset uint64, length uint32, payload []byte) error {
	if len(payload) > math.MaxUint32 {
		return errors.New("payload size exceeds protocol limit")
	}

	header := nbdproto.RequestHeader{
		Magic:  nbdproto.REQUEST_MAGIC,
		Flags:  cflags,
		Type:   ty,
		Cookie: cookie,
		Offset: offset,
		Length: length,
	}
	if l := len(payload); l > 0 {
		header.Length = uint32(l)
	}
	psize := int(unsafe.Sizeof(header)) + len(payload)
	packet := bytes.NewBuffer(make([]byte, 0, psize))
	if err := binary.Write(packet, binary.BigEndian, header); err != nil {
		return err
	}
	if err := binary.Write(packet, binary.BigEndian, payload); err != nil {
		return err
	}
	if _, err := io.Copy(server, packet); err != nil {
		return err
	}
	return nil
}

func isTXError(type_ uint16) bool {
	return type_&(1<<15) != 0
}
