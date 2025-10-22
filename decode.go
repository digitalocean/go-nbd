// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

type transmissionErrorDecoder struct {
	hdr transmissionHeader
	buf []byte
	r   io.Reader
}

func (d transmissionErrorDecoder) Decode(t *TransmissionError) error {
	if hdr := d.hdr.simple; hdr != nil {
		*t = TransmissionError{
			Code: TransmissionErrorCode(hdr.Error),
		}
		return nil
	}

	hdr := d.hdr.structured

	var code uint32
	if err := binary.Read(d.r, binary.BigEndian, &code); err != nil {
		return fmt.Errorf("read error code: %w", err)
	}

	var length uint16
	if err := binary.Read(d.r, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read error string length: %w", err)
	}

	var offset uint64
	if hdr.Type == nbdproto.REPLY_TYPE_ERROR_OFFSET {
		if err := binary.Read(d.r, binary.BigEndian, &offset); err != nil {
			return fmt.Errorf("read error offset: %w", err)
		}
	}

	if int(length) > len(d.buf) {
		return errPayloadTooLarge
	}

	buf := d.buf[:length]
	if len(buf) > 0 {
		_, err := io.ReadFull(d.r, buf)
		if err != nil {
			return fmt.Errorf("read error string: %w", err)
		}
	}

	*t = TransmissionError{
		Code: TransmissionErrorCode(code),
		Message: NullErrorMessage{
			Value: string(buf),
			Valid: len(buf) > 0,
		},
		Offset: NullOffset{
			Value: offset,
			Valid: hdr.Type == nbdproto.REPLY_TYPE_ERROR_OFFSET,
		},
	}

	return nil
}
