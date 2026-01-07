// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

func TestDefaultBufferSizeFitsMaxNBDStringLength(t *testing.T) {
	if DefaultBufferSize < nbdproto.MaximumStringLength {
		t.Errorf("DefaultBufferSize should be >= %d",
			nbdproto.MaximumStringLength)
	}
}

// mockConn implements net.Conn for testing purposes.
type mockConn struct {
	r io.Reader
	w io.Writer
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return m.r.Read(b) }
func (m *mockConn) Write(b []byte) (n int, err error)  { return m.w.Write(b) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestConn(response []byte) *Conn {
	buflk := make(chan struct{}, 1)
	buflk <- struct{}{}

	conn := &Conn{
		conn:  &mockConn{r: bytes.NewReader(response), w: io.Discard},
		buflk: buflk,
		buf:   make([]byte, DefaultBufferSize),
	}
	conn.state_.Store(int32(connectionStateTransmission))
	// cookie starts at 0; Read will Add(1) to get 1 as the first cookie

	return conn
}

// writeStructuredHoleChunk writes a structured reply chunk for a hole.
func writeStructuredHoleChunk(w *bytes.Buffer, cookie uint64, flags uint16, offset uint64, length uint32) {
	binary.Write(w, binary.BigEndian, nbdproto.NBD_STRUCTURED_REPLY_MAGIC)
	binary.Write(w, binary.BigEndian, flags)
	binary.Write(w, binary.BigEndian, nbdproto.REPLY_TYPE_OFFSET_HOLE)
	binary.Write(w, binary.BigEndian, cookie)
	binary.Write(w, binary.BigEndian, uint32(12)) // length of hole payload
	binary.Write(w, binary.BigEndian, offset)
	binary.Write(w, binary.BigEndian, length)
}

// writeStructuredDataChunk writes a structured reply chunk for data.
func writeStructuredDataChunk(w *bytes.Buffer, cookie uint64, flags uint16, offset uint64, data []byte) {
	binary.Write(w, binary.BigEndian, nbdproto.NBD_STRUCTURED_REPLY_MAGIC)
	binary.Write(w, binary.BigEndian, flags)
	binary.Write(w, binary.BigEndian, nbdproto.REPLY_TYPE_OFFSET_DATA)
	binary.Write(w, binary.BigEndian, cookie)
	binary.Write(w, binary.BigEndian, uint32(8+len(data))) // offset + data
	binary.Write(w, binary.BigEndian, offset)
	w.Write(data)
}

func TestReadOverlappingChunks(t *testing.T) {
	tests := []struct {
		name        string
		bufSize     int
		readOffset  uint64
		buildReply  func(cookie uint64) []byte
		wantErrText string
	}{
		{
			name:       "overlapping hole chunks",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				// First hole: [0, 256)
				writeStructuredHoleChunk(&buf, cookie, 0, 0, 256)
				// Second hole: [128, 384) - overlaps with first
				writeStructuredHoleChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 128, 256)
				return buf.Bytes()
			},
			wantErrText: "overlapping hole chunk",
		},
		{
			name:       "overlapping data chunks",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				data := make([]byte, 256)
				// First data: [0, 256)
				writeStructuredDataChunk(&buf, cookie, 0, 0, data)
				// Second data: [128, 384) - overlaps with first
				writeStructuredDataChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 128, data)
				return buf.Bytes()
			},
			wantErrText: "overlapping data chunk",
		},
		{
			name:       "hole overlaps with data",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				data := make([]byte, 256)
				// First: data [0, 256)
				writeStructuredDataChunk(&buf, cookie, 0, 0, data)
				// Second: hole [128, 384) - overlaps with data
				writeStructuredHoleChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 128, 256)
				return buf.Bytes()
			},
			wantErrText: "overlapping hole chunk",
		},
		{
			name:       "data overlaps with hole",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				data := make([]byte, 256)
				// First: hole [0, 256)
				writeStructuredHoleChunk(&buf, cookie, 0, 0, 256)
				// Second: data [128, 384) - overlaps with hole
				writeStructuredDataChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 128, data)
				return buf.Bytes()
			},
			wantErrText: "overlapping data chunk",
		},
		{
			name:       "identical hole chunks",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				// Two identical holes: [0, 512)
				writeStructuredHoleChunk(&buf, cookie, 0, 0, 512)
				writeStructuredHoleChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 0, 512)
				return buf.Bytes()
			},
			wantErrText: "overlapping hole chunk",
		},
		{
			name:       "adjacent chunks do not overlap",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				// First hole: [0, 256)
				writeStructuredHoleChunk(&buf, cookie, 0, 0, 256)
				// Second hole: [256, 512) - adjacent, not overlapping
				writeStructuredHoleChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 256, 256)
				return buf.Bytes()
			},
			wantErrText: "", // no error expected
		},
		{
			name:       "non-overlapping chunks with gap",
			bufSize:    512,
			readOffset: 0,
			buildReply: func(cookie uint64) []byte {
				var buf bytes.Buffer
				// First hole: [0, 128)
				writeStructuredHoleChunk(&buf, cookie, 0, 0, 128)
				// Second hole: [384, 512) - no overlap
				writeStructuredHoleChunk(&buf, cookie, nbdproto.REPLY_FLAG_DONE, 384, 128)
				return buf.Bytes()
			},
			wantErrText: "", // no error expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Read does cookie.Add(1), so with cookie starting at 0, the first
			// request will use cookie value 1.
			const expectedCookie uint64 = 1

			reply := tt.buildReply(expectedCookie)
			conn := newTestConn(reply)

			buf := make([]byte, tt.bufSize)
			_, err := conn.Read(buf, tt.readOffset, 0)

			if tt.wantErrText == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErrText)
				} else if !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("expected error containing %q, got %q", tt.wantErrText, err.Error())
				}
			}
		})
	}
}
