// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

func Test_readOptionReply_InvalidMagic(t *testing.T) {
	tests := []struct {
		magic     uint64
		wantError string
	}{
		{
			magic: uint64(0xce),
			wantError: fmt.Sprintf("got %#x magic, want %#x",
				uint64(0xce), nbdproto.REPLY_MAGIC),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%x", tt.magic), func(t *testing.T) {
			hdr := nbdproto.OptionReplyHeader{
				Magic: tt.magic,
			}

			var buf bytes.Buffer
			err := binary.Write(&buf, binary.BigEndian, hdr)
			if err != nil {
				t.Fatalf("set up input buffer: %v", err)
			}

			_, err = readOptionReply(&buf, nil)
			if err == nil || err.Error() != tt.wantError {
				t.Errorf("got err=\"%v\", want err=%q", err, tt.wantError)
			}
		})
	}
}
