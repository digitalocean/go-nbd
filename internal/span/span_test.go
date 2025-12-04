// SPDX-License-Identifier: Apache-2.0

package span

import (
	"fmt"
	"testing"
)

func TestSpanContains(t *testing.T) {
	tests := []struct {
		a, b Span[int]
		want bool
	}{
		{a: Span[int]{5, 10}, b: Span[int]{6, 10}, want: true},
		{a: Span[int]{4, 9}, b: Span[int]{1, 5}, want: false},
		{a: Span[int]{1, 3}, b: Span[int]{1, 3}, want: true},
		{a: Span[int]{0, 5}, b: Span[int]{6, 10}, want: false},
		{a: Span[int]{0, 5}, b: Span[int]{0, 5}, want: true},
		{a: Span[int]{0, 5}, b: Span[int]{3, 5}, want: true},
		{a: Span[int]{0, 5}, b: Span[int]{3, 6}, want: false},
		{a: Span[int]{0, 5}, b: Span[int]{2, 3}, want: true},
	}

	for _, tt := range tests {
		result := "contains"
		if !tt.want {
			result = "does not contain"
		}

		name := fmt.Sprintf("(%d, %d) %s (%d, %d)",
			tt.a.Start, tt.a.End, result, tt.b.Start, tt.b.End)

		t.Run(name, func(t *testing.T) {
			got := tt.a.Contains(tt.b)

			if got != tt.want {
				t.Errorf("want %v, got %v", tt.want, got)
			}
		})
	}
}
