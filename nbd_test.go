// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"context"
	"crypto/tls"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/digitalocean/go-nbd/nbdmeta"
)

func TestNBD(t *testing.T) {
	tests := []struct {
		name     string
		provider func(t *testing.T, size uint64) (uri string, tlsConf *tls.Config, cleanup func())
		size     uint64
	}{
		{
			name: "nbd unix",
			size: 8 * megabyte,
			provider: func(t *testing.T, size uint64) (uri string, tlsConf *tls.Config, cleanup func()) {
				d := t.TempDir()
				socket := filepath.Join(d, "nbd-test.sock")
				cleanup, err := provideNBDUnix(t, socket, size)
				if err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("nbd+unix://?socket=%s", socket), nil, cleanup
			},
		},
		{
			name: "nbds unix",
			size: 8 * megabyte,
			provider: func(t *testing.T, size uint64) (uri string, tlsConf *tls.Config, cleanup func()) {
				socketDir := t.TempDir()
				pkiDir := t.TempDir()

				socket := filepath.Join(socketDir, "nbds-test.sock")
				tlsConf, cleanup, err := provideSecureNBDUnix(t, socket, size, pkiDir)
				if err != nil {
					t.Fatal(err)
				}

				return fmt.Sprintf("nbds+unix://?socket=%s", socket), tlsConf, cleanup
			},
		},
		{
			name: "nbd tcp",
			size: 8 * megabyte,
			provider: func(t *testing.T, size uint64) (uri string, tlsConf *tls.Config, cleanup func()) {
				pidfileDir := t.TempDir()

				port := 10809

				pidfile := filepath.Join(pidfileDir, "nbdkit.pid")
				cleanup, err := provideNBD(t, pidfile, size, port)
				if err != nil {
					t.Fatal(err)
				}

				return fmt.Sprintf("nbd://localhost:%d", port), nil, cleanup
			},
		},
		{
			name: "nbds tcp",
			size: 8 * megabyte,
			provider: func(t *testing.T, size uint64) (uri string, tlsConf *tls.Config, cleanup func()) {
				pidfileDir := t.TempDir()
				pkiDir := t.TempDir()

				port := 10810

				pidfile := filepath.Join(pidfileDir, "nbdkit.pid")
				tlsConf, cleanup, err := provideSecureNBD(t, pidfile, size, port, pkiDir)
				if err != nil {
					t.Fatal(err)
				}

				return fmt.Sprintf("nbds://localhost:%d", port), tlsConf, cleanup
			},
		},
	}

	for _, tt := range tests {
		_, err := exec.LookPath(nbdkitBin)
		if err != nil {
			t.Skip(err)
		}

		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			u, tlsConf, cleanup := tt.provider(t, tt.size)
			defer cleanup()

			uri, err := ParseURI(u)
			if err != nil {
				t.Errorf("parse NBD URI: %v", err)
				return
			}

			dialer := new(Dialer)
			conn, err := dialer.Dial(ctx, uri)
			if err != nil {
				t.Fatalf("dial: %v", err)
				return
			}
			defer func() {
				t.Helper()
				if err := conn.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}()

			err = conn.Connect()
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer func() {
				t.Helper()
				if err := conn.Abort(); err != nil {
					t.Errorf("abort: %v", err)
				}
			}()

			if tlsConf != nil {
				err := conn.StartTLS(tlsConf)
				if err != nil {
					t.Errorf("start tls: %v", err)
				}
			}

			exports, err := conn.List()
			if err != nil {
				t.Errorf("list: %v", err)
			}

			if len(exports) != 1 {
				t.Fatalf("want len(exports) == 1, got len(exports) == %d", len(exports))
			}

			export := exports[0]

			err = conn.StructuredReplies()
			if err != nil {
				t.Fatalf("set structured replies: %v", err)
			}

			metacontexts, err := conn.ListMetaContext(export)
			if err != nil {
				t.Fatalf("list meta contexts: %v", err)
			}

			index := slices.IndexFunc(metacontexts, func(c MetaContext) bool {
				return c.Name == "base:allocation"
			})
			if index == -1 {
				t.Fatal("did not find base:allocation meta context")
			}

			setcontexts, err := conn.SetMetaContext(export, metacontexts[index].Name)
			if err != nil {
				t.Fatalf("set base:allocation as meta context: %v", err)
			}

			if !cmp.Equal(metacontexts, setcontexts) {
				t.Fatal(cmp.Diff(metacontexts, setcontexts))
			}

			info, err := conn.Info(export, InfoRequestAll())
			if err != nil {
				t.Fatalf("info: %v", err)
			}

			if info.Size != tt.size {
				t.Errorf("want size=%d, got size=%d", tt.size, info.Size)
			}

			info2, err := conn.Go(export, InfoRequestAll())
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			defer func() {
				if err := conn.Disconnect(); err != nil {
					t.Fatalf("disconnect: %v", err)
				}
			}()

			if !cmp.Equal(info, info2) {
				t.Error(cmp.Diff(info, info2))
			}

			data := make([]byte, 512)
			for i := 0; i < len(data); i++ {
				data[i] = 0xce
			}
			err = conn.Write(CommandFlags(0), 0, data)
			if err != nil {
				t.Errorf("write 512 0xce to offset 0: %v", err)
			}

			err = conn.Flush(CommandFlags(0))
			if err != nil {
				t.Errorf("flush: %v", err)
			}

			err = conn.Cache(CommandFlags(0), 512, 512)
			if err != nil {
				t.Errorf("cache 512, 1024: %v", err)
			}

			readData, err := conn.Read(CommandFlags(0), 0, 512)
			if err != nil {
				t.Errorf("read first 512: %v", err)
			}

			got := make([]byte, len(data))
			for _, r := range readData {
				copy(got[r.Data.Offset:], r.Data.Data)
			}

			if !cmp.Equal(data, got) {
				t.Error(t, cmp.Diff(data, got))
			}

			status, err := conn.BlockStatus(CommandFlags(0), 0, 1024)
			if err != nil {
				t.Errorf("block status: %v", err)
			}

			if len(status.Descriptors) == 0 {
				t.Errorf("want len(descriptors) > 0, got len(descriptors) == 0: %+v", status.Descriptors)
			}

			alloc := nbdmeta.BaseAllocationFlags(status.Descriptors[0].Status)
			if !alloc.Allocated() {
				t.Errorf("first 512 bytes are not allocated, but should be %x", alloc)
			}

			err = conn.WriteZeroes(CommandFlags(0), 0, 512)
			if err != nil {
				t.Errorf("overwrite first 512 with zeroes: %v", err)
			}

			readData, err = conn.Read(CommandFlags(0), 0, 512)
			if err != nil {
				t.Errorf("read first 512: %v", err)
			}

			got = make([]byte, len(data))
			for _, r := range readData {
				copy(got[r.Data.Offset:], r.Data.Data)
			}

			zeroes := make([]byte, 512)
			if !cmp.Equal(zeroes, got) {
				t.Error(cmp.Diff(zeroes, got))
			}

			err = conn.Trim(CommandFlags(0), 0, 512)
			if err != nil {
				t.Errorf("trim first 512: %v", err)
			}
		})
	}
}
