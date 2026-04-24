// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

func Test_transmissionHeader_DecodeFrom_UnnegotiatedStructuredReplies(t *testing.T) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, nbdproto.NBD_STRUCTURED_REPLY_MAGIC)
	if err != nil {
		t.Fatalf("set up input buffer: %v", err)
	}

	hdr := transmissionHeader{
		structuredReplies: false,
	}

	var errString string
	err = hdr.DecodeFrom(&buf)
	if err != nil {
		errString = err.Error()
	}

	want := "got unnegotiated NBD_STRUCTURED_REPLY_MAGIC"
	if errString != want {
		t.Errorf("got %q, want %q", errString, want)
	}
}
