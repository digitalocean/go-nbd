// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

// InfoRequest allows changing the scope of what is returned
// from an Info or Go call.
type InfoRequest uint16

const (
	InfoRequestExport      InfoRequest = InfoRequest(nbdproto.INFO_EXPORT)
	InfoRequestName        InfoRequest = InfoRequest(nbdproto.INFO_NAME)
	InfoRequestDescription InfoRequest = InfoRequest(nbdproto.INFO_DESCRIPTION)
	InfoRequestBlockSize   InfoRequest = InfoRequest(nbdproto.INFO_BLOCK_SIZE)
)

// InfoRequestAll is the default set of InfoRequests. Pass this
// in as a default value in calls to conn.Go or conn.Info unless
// you have a specific preference otherwise.
func InfoRequestAll() []InfoRequest {
	return []InfoRequest{
		InfoRequestName,
		InfoRequestDescription,
		InfoRequestBlockSize,
		InfoRequestExport,
	}
}

// ExportInfo describes the export.
type ExportInfo struct {
	Name               string
	Description        string
	Size               uint64
	TransmissionFlags  uint16
	MinBlockSize       uint32
	PreferredBlockSize uint32
	MaxBlockSize       uint32
}

// MetaContext is a human-readable description of a meta
// context.
type MetaContext struct {
	Name string
}

type optionReply struct {
	OptID   uint32
	Type    uint32
	Payload []byte
}

type empty struct{}

func (*empty) Serialize(*bytes.Buffer) error { return nil }

type exportNameRequest struct {
	export string
}

func (e *exportNameRequest) ID() uint32 { return nbdproto.OPT_EXPORT_NAME }

func (e *exportNameRequest) Serialize(buf *bytes.Buffer) error {
	return binary.Write(buf, binary.BigEndian, []byte(e.export))
}

type abortRequest struct {
	empty
}

func (*abortRequest) ID() uint32 { return nbdproto.OPT_ABORT }

type listExportsRequest struct {
	empty
}

func (*listExportsRequest) ID() uint32 { return nbdproto.OPT_LIST }

type infoGoRequest struct {
	export   string
	requests []InfoRequest
}

func (i *infoGoRequest) Serialize(buf *bytes.Buffer) error {
	err := binary.Write(buf, binary.BigEndian, uint32(len(i.export)))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, []byte(i.export))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, uint16(len(i.requests)))
	if err != nil {
		return err
	}
	for _, request := range i.requests {
		err := binary.Write(buf, binary.BigEndian, uint16(request))
		if err != nil {
			return err
		}
	}
	return nil
}

type startTLSRequest struct {
	empty
}

func (*startTLSRequest) ID() uint32 { return nbdproto.OPT_STARTTLS }

type infoRequest struct {
	infoGoRequest
}

func (*infoRequest) ID() uint32 { return nbdproto.OPT_INFO }

type goRequest struct {
	infoGoRequest
}

func (*goRequest) ID() uint32 { return nbdproto.OPT_GO }

type structuredRepliesRequest struct {
	empty
}

func (*structuredRepliesRequest) ID() uint32 { return nbdproto.OPT_STRUCTURED_REPLY }

type listMetaContextsRequest struct {
	export  string
	queries []string
}

func (l *listMetaContextsRequest) ID() uint32 { return nbdproto.OPT_LIST_META_CONTEXT }

func (l *listMetaContextsRequest) Serialize(buf *bytes.Buffer) error {
	err := binary.Write(buf, binary.BigEndian, uint32(len(l.export)))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, []byte(l.export))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, uint32(len(l.queries)))
	if err != nil {
		return err
	}
	for _, query := range l.queries {
		err := binary.Write(buf, binary.BigEndian, uint32(len(query)))
		if err != nil {
			return err
		}
		err = binary.Write(buf, binary.BigEndian, []byte(query))
		if err != nil {
			return err
		}
	}
	return nil
}

type setMetaContext struct {
	export  string
	queries []string
}

func (s *setMetaContext) ID() uint32 { return nbdproto.OPT_SET_META_CONTEXT }

func (s *setMetaContext) Serialize(buf *bytes.Buffer) error {
	err := binary.Write(buf, binary.BigEndian, uint32(len(s.export)))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, []byte(s.export))
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, uint32(len(s.queries)))
	if err != nil {
		return err
	}
	for _, query := range s.queries {
		err := binary.Write(buf, binary.BigEndian, uint32(len(query)))
		if err != nil {
			return err
		}
		err = binary.Write(buf, binary.BigEndian, []byte(query))
		if err != nil {
			return err
		}
	}
	return nil
}

type ack struct{}

func (*ack) UnmarshalNBDReply(data []byte) error {
	return nil
}

type repExportName struct {
	ExportSize        uint64
	TransmissionFlags TransmissionFlags
}

type repServer struct {
	Length uint32
	Name   string
}

func (r *repServer) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, &r.Length)
	if err != nil {
		return err
	}
	name := make([]byte, buf.Len())
	err = binary.Read(buf, binary.BigEndian, name)
	if err != nil {
		return err
	}
	r.Name = string(name)
	return nil
}

type repInfo struct {
	Type    uint16
	Payload []byte
}

func (r *repInfo) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewBuffer(data)
	err := binary.Read(buf, binary.BigEndian, &r.Type)
	if err != nil {
		return err
	}
	r.Payload = buf.Bytes()
	return nil
}

type repInfoExport struct {
	Size  uint64
	Flags uint16
}

func (r *repInfoExport) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, r)
}

type repInfoName struct {
	Name string
}

func (r *repInfoName) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewBuffer(data)
	name := make([]byte, buf.Len())
	err := binary.Read(buf, binary.BigEndian, name)
	if err != nil {
		return err
	}
	r.Name = string(name)
	return nil
}

type repInfoDescription struct {
	Description string
}

func (r *repInfoDescription) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewBuffer(data)
	desc := make([]byte, buf.Len())
	err := binary.Read(buf, binary.BigEndian, desc)
	if err != nil {
		return err
	}
	r.Description = string(desc)
	return nil
}

type repInfoBlockSize struct {
	MinimumBlockSize   uint32
	PreferredBlockSize uint32
	MaximumBlockSize   uint32
}

func (r *repInfoBlockSize) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, r)
}

type repMetaContext struct {
	ID   uint32
	Name string
}

func (r *repMetaContext) UnmarshalNBDReply(data []byte) error {
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, &r.ID)
	if err != nil {
		return err
	}
	// FIXME if len(data.Payload) < 4
	name := make([]byte, buf.Len())
	err = binary.Read(buf, binary.BigEndian, name)
	if err != nil {
		return err
	}
	r.Name = string(name)
	return nil
}

type option interface {
	ID() uint32
	Serialize(buf *bytes.Buffer) error
}

func requestOption(server io.Writer, opt option) error {
	payload := bytes.NewBuffer(make([]byte, 0, 128))
	if err := opt.Serialize(payload); err != nil {
		return err
	}
	header := nbdproto.OptionHeader{
		Magic:  nbdproto.HAVE_OPT,
		ID:     opt.ID(),
		Length: uint32(payload.Len()),
	}
	packet := bytes.NewBuffer(make([]byte, 0, uint32(unsafe.Sizeof(header))+header.Length))
	if err := binary.Write(packet, binary.BigEndian, header); err != nil {
		return err
	}
	if err := binary.Write(packet, binary.BigEndian, payload.Bytes()); err != nil {
		return err
	}
	if _, err := io.Copy(server, packet); err != nil {
		return err
	}
	return nil
}

func readOptionReply(server io.Reader, buf []byte) (optionReply, error) {
	var header nbdproto.OptionReplyHeader
	if err := binary.Read(server, binary.BigEndian, &header); err != nil {
		return optionReply{}, err
	}

	if int(header.Length) > len(buf) {
		return optionReply{}, errPayloadTooLarge
	}

	buf = buf[:header.Length]

	if _, err := io.ReadFull(server, buf); err != nil {
		return optionReply{}, fmt.Errorf("read option reply payload: %w", err)
	}
	if isOptError(header.Type) {
		return optionReply{}, toOptError(header.Type, buf)
	}
	return optionReply{
		OptID:   header.ID,
		Type:    header.Type,
		Payload: buf,
	}, nil
}

func isOptError(id uint32) bool {
	return id&(1<<31) != 0
}

func toOptError(id uint32, payload []byte) error {
	message := string(payload)
	return &NegotiationError{
		Code: OptionErrorCode(id),
		Message: NullErrorMessage{
			Value: message,
			Valid: len(message) > 0,
		},
	}
}
