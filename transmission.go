// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

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

// readHole indicates this extent is a hole.
type readHole struct {
	Offset uint64
	Length uint32
}

func (r *readHole) UnmarshalNBDReply(data []byte) error {
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

type transmissionHeader struct {
	simple     *nbdproto.SimpleReplyHeader
	structured *nbdproto.StructuredReplyHeader
}

func (t *transmissionHeader) DecodeFrom(r io.Reader) error {
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	if magic != nbdproto.NBD_SIMPLE_REPLY_MAGIC && magic != nbdproto.NBD_STRUCTURED_REPLY_MAGIC {
		return fmt.Errorf("got invalid magic %x", magic)
	}
	if magic == nbdproto.NBD_SIMPLE_REPLY_MAGIC {
		hdr := nbdproto.SimpleReplyHeader{
			Magic: magic,
		}

		if err := binary.Read(r, binary.BigEndian, &hdr.Error); err != nil {
			return fmt.Errorf("simple: read error: %w", err)
		}
		if err := binary.Read(r, binary.BigEndian, &hdr.Cookie); err != nil {
			return fmt.Errorf("simple: read cookie: %w", err)
		}

		t.simple = &hdr
		return nil
	}

	hdr := nbdproto.StructuredReplyHeader{
		Magic: nbdproto.NBD_STRUCTURED_REPLY_MAGIC,
	}

	if err := binary.Read(r, binary.BigEndian, &hdr.Flags); err != nil {
		return fmt.Errorf("structured: read flags: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &hdr.Type); err != nil {
		return fmt.Errorf("structured: read type: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &hdr.Cookie); err != nil {
		return fmt.Errorf("structured: read cookie: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &hdr.Length); err != nil {
		return fmt.Errorf("structured: read length: %w", err)
	}

	t.structured = &hdr
	return nil
}

func (t *transmissionHeader) IsErr() bool {
	if hdr := t.simple; hdr != nil {
		return hdr.Error != 0
	}
	if hdr := t.structured; hdr != nil {
		return isTXError(hdr.Type)
	}
	return false
}

func oneShotTransmit(
	server io.ReadWriter,
	cflags uint16,
	type_ uint16,
	cookie uint64,
	offset uint64,
	length uint32,
	payload []byte,
	buf []byte,
) error {
	err := requestTransmit(server, cflags, type_, cookie, offset, length, payload)
	if err != nil {
		return err
	}

	var hdr transmissionHeader
	err = hdr.DecodeFrom(server)
	if err != nil {
		return err
	}

	if hdr.simple == nil && hdr.structured == nil {
		return errors.New("invalid enum state for transmissionHeader")
	}

	cookieMismatch := errors.New("cookie mismatch")

	if hdr.simple != nil && hdr.simple.Cookie != cookie {
		return cookieMismatch
	}

	if hdr.structured != nil && hdr.structured.Cookie != cookie {
		return cookieMismatch
	}

	if hdr.IsErr() {
		var terr TransmissionError
		d := transmissionErrorDecoder{
			hdr: hdr,
			buf: buf,
			r:   server,
		}
		if err := d.Decode(&terr); err != nil {
			return err
		}
		return &terr
	}

	if hdr.simple != nil {
		return nil
	}

	if hdr.structured.Type != nbdproto.REPLY_TYPE_NONE {
		return fmt.Errorf("unexpected REP_TYPE %d, expected %d",
			hdr.structured.Type, nbdproto.REPLY_TYPE_NONE)
	}

	if hdr.structured.Flags&nbdproto.REPLY_FLAG_DONE != 0 {
		return errors.New("server sent NBD_REP_TYPE_NONE without REPLY_FLAG_DONE")
	}

	return nil
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

	if err := binary.Write(server, binary.BigEndian, header); err != nil {
		return err
	}

	if len(payload) == 0 {
		return nil
	}

	if err := binary.Write(server, binary.BigEndian, payload); err != nil {
		return err
	}

	return nil
}

func isTXError(type_ uint16) bool {
	return type_&(1<<15) != 0
}
