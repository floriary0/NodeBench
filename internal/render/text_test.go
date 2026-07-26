package render

import "testing"

func TestGibibytesKeepsSmallMemoryVisible(t *testing.T) {
	if got := gibibytes(492826624); got != "0.5" {
		t.Fatalf("gibibytes = %q, want 0.5", got)
	}
	if got := gibibytes(2 << 30); got != "2" {
		t.Fatalf("gibibytes = %q, want 2", got)
	}
}
