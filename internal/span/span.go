// SPDX-License-Identifier: Apache-2.0

package span

import (
	"fmt"
)

type Number interface {
	~int | ~uint64
}

// Span represents the span between two points on a number line (inclusive).
//
// See [Span.Check] for constraints on how this type should be used.
type Span[T Number] struct {
	Start, End T
}

// Check asserts that the span has a positive, non-zero length (that is,
// start < end.)
func (s Span[T]) Check() error {
	if s.Start < s.End {
		return nil
	}
	return fmt.Errorf("bad span: start must precede end [%d,%d]", s.Start, s.End)
}

// Contains returns true if the other span is completely contained
// by the receiving span. It returns false even for partially overlapping
// spans.
func (s Span[T]) Contains(other Span[T]) bool {
	return other.Start >= s.Start && other.End <= s.End
}

// Overlaps returns true if the two spans share any common region.
func (s Span[T]) Overlaps(other Span[T]) bool {
	return s.Start < other.End && other.Start < s.End
}
