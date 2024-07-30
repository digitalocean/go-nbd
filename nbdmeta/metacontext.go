// SPDX-License-Identifier: Apache-2.0

package nbdmeta

import "strings"

type BaseAllocationFlags uint32

const (
	BaseAllocationFlagHole BaseAllocationFlags = 1 << 0
	BaseAllocationFlagZero BaseAllocationFlags = 1 << 1
)

func (f BaseAllocationFlags) Allocated() bool {
	return f&BaseAllocationFlagHole == 0
}

func (f BaseAllocationFlags) Hole() bool {
	return f&BaseAllocationFlagHole != 0
}

func (f BaseAllocationFlags) Zero() bool {
	return f&BaseAllocationFlagZero != 0
}

func (f BaseAllocationFlags) String() string {
	if f.Allocated() {
		return "data"
	}

	var s []string
	if f&BaseAllocationFlagHole != 0 {
		s = append(s, "hole")
	}
	if f&BaseAllocationFlagZero != 0 {
		s = append(s, "zero")
	}
	return strings.Join(s, ",")
}

type DirtyBitmapFlags uint32

const (
	DirtyBitmapFlagDirty DirtyBitmapFlags = 1 << 0
)

func (f DirtyBitmapFlags) Dirty() bool {
	return f&DirtyBitmapFlagDirty != 0
}

func (f DirtyBitmapFlags) String() string {
	if f&DirtyBitmapFlagDirty == 0 {
		return ""
	}
	return "dirty"
}
