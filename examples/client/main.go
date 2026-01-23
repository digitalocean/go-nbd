// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/digitalocean/go-nbd"
	"github.com/digitalocean/go-nbd/nbdmeta"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func run() error {
	uri := nbd.MustURI(os.Getenv("EXAMPLE_NBD_URI"))

	var dialer nbd.Dialer
	conn, err := dialer.Dial(context.TODO(), uri)
	if err != nil {
		return fmt.Errorf("nbd dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	err = conn.Connect()
	if err != nil {
		return fmt.Errorf("nbd connect: %w", err)
	}
	defer func() { _ = conn.Abort() }()

	var exports []string
	err = conn.List(func(export string) error {
		exports = append(exports, export)
		return nil
	})
	if err != nil {
		return fmt.Errorf("nbd list: %w", err)
	}
	if len(exports) == 0 {
		return fmt.Errorf("nbd: no exports")
	}
	name := exports[0]
	info, err := conn.Info(name, nbd.InfoRequestAll())
	if err != nil {
		return fmt.Errorf("nbd: info: %w", err)
	}
	fmt.Printf("info %+v\n", info)
	var metas []nbd.MetaContext
	err = conn.ListMetaContext(name, nil, func(m nbd.MetaContext) error {
		metas = append(metas, m)
		return nil
	})
	if err != nil {
		return fmt.Errorf("nbd: list meta context: %w", err)
	}
	fmt.Printf("meta contexts %+v\n", metas)
	if len(metas) == 0 {
		return nil
	}
	err = conn.StructuredReplies()
	if err != nil {
		return fmt.Errorf("nbd: set structured replies: %w", err)
	}
	err = conn.SetMetaContext(name, []string{metas[0].Name}, func(_ nbd.MetaContext) error { return nil })
	if err != nil {
		return fmt.Errorf("nbd: set meta context: %w", err)
	}
	size, _, err := conn.ExportName(name)
	if err != nil {
		return fmt.Errorf("nbd: export name: %w", err)
	}
	defer func() { _ = conn.Disconnect() }()

	var (
		status nbd.BlockStatus
		stop   bool
	)

	iterator := func(b nbd.BlockStatus) error {
		// Just accepting 1 chunk for the sake of example.
		if !stop {
			stop = true
			status = b
		}
		return nil
	}

	// Note, you'll want to do something smarter for the length
	// field if your export is larger than math.MaxUint32.
	err = conn.BlockStatus(0, uint32(size), iterator, 0)
	if err != nil {
		return fmt.Errorf("nbd: block status: %w", err)
	}
	fmt.Println("allocation map")
	var offset uint32
	for _, d := range status.Descriptors {
		a := nbdmeta.BaseAllocationFlags(d.Status)
		fmt.Printf("%10d: %d bytes %v\n", offset, d.Length, a)
		offset += d.Length
	}
	err = conn.Cache(0, 0, 512)
	if err != nil {
		return fmt.Errorf("nbd: cache: %w", err)
	}
	_, err = conn.Read(make([]byte, 512), 0, 0)
	if err != nil {
		return fmt.Errorf("nbd: read: %w", err)
	}
	return nil
}
