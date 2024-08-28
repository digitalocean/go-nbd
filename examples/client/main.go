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
	ctx := context.TODO()

	uri := nbd.MustURI(os.Getenv("EXAMPLE_NBD_URI"))

	var dialer nbd.Dialer
	conn, err := dialer.Dial(context.TODO(), uri)
	if err != nil {
		return fmt.Errorf("nbd dial: %w", err)
	}
	defer conn.Close()
	err = conn.Connect(ctx)
	if err != nil {
		return fmt.Errorf("nbd connect: %w", err)
	}
	defer conn.Abort(ctx)
	exports, err := conn.List(ctx)
	if err != nil {
		return fmt.Errorf("nbd list: %w", err)
	}
	if len(exports) == 0 {
		return fmt.Errorf("nbd: no exports")
	}
	name := exports[0]
	info, err := conn.Info(ctx, name, nbd.InfoRequestAll())
	if err != nil {
		return fmt.Errorf("nbd: info: %w", err)
	}
	fmt.Printf("info %+v\n", info)
	metas, err := conn.ListMetaContext(ctx, name)
	if err != nil {
		return fmt.Errorf("nbd: list meta context: %w", err)
	}
	fmt.Printf("meta contexts %+v\n", metas)
	if len(metas) == 0 {
		return nil
	}
	err = conn.StructuredReplies(ctx)
	if err != nil {
		return fmt.Errorf("nbd: set structured replies: %w", err)
	}
	_, err = conn.SetMetaContext(ctx, name, metas[0].Name)
	if err != nil {
		return fmt.Errorf("nbd: set meta context: %w", err)
	}
	size, _, err := conn.ExportName(ctx, name)
	if err != nil {
		return fmt.Errorf("nbd: export name: %w", err)
	}
	defer conn.Disconnect(ctx)

	// Note, you'll want to do something smarter for the length
	// field if your export is larger than math.MaxUint32.
	status, err := conn.BlockStatus(ctx, 0, 0, uint32(size))
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
	err = conn.Cache(ctx, 0, 0, 512)
	if err != nil {
		return fmt.Errorf("nbd: cache: %w", err)
	}
	_, err = conn.Read(ctx, 0, 0, 512)
	if err != nil {
		return fmt.Errorf("nbd: read: %w", err)
	}
	return nil
}
