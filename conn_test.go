// SPDX-License-Identifier: Apache-2.0

package nbd

import (
	"testing"

	"github.com/digitalocean/go-nbd/internal/nbdproto"
)

func TestDefaultBufferSizeFitsMaxNBDStringLength(t *testing.T) {
	if DefaultBufferSize < nbdproto.MaximumStringLength {
		t.Errorf("DefaultBufferSize should be >= %d",
			nbdproto.MaximumStringLength)
	}
}
