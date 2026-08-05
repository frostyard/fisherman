package secure_test

import (
	"testing"

	"github.com/tuna-os/fisherman/internal/secure"
)

// Debian version ordering, including the cases that make a naive string or
// semver comparison wrong.
func TestDebCompare(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want int
		why  string
	}{
		{"261.1-3", "261.1-3", 0, "identical"},
		{"261.2-1", "261.1-3", 1, "the drift that motivated the floor"},
		{"261.1-2", "261.1-3", -1, "older revision"},
		{"261.10-1", "261.9-1", 1, "numeric, not lexical: 10 > 9"},
		{"261.1-10", "261.1-9", 1, "numeric in the revision too"},
		{"262", "261.99-9", 1, "upstream dominates revision"},
		{"1:1.0-1", "2.0-1", 1, "a higher epoch wins regardless of upstream"},
		{"1.0~rc1", "1.0", -1, "tilde sorts before end of part"},
		{"1.0", "1.0~rc1", 1, "and the reverse"},
		{"1.0-1", "1.0", 1, "a revision is newer than none"},
		{"2.6.1", "2.6.1", 0, "cosign floor, equal"},
		{"2.7.0", "2.6.1", 1, "cosign floor, newer"},
	} {
		if got := secure.DebCompare(test.a, test.b); got != test.want {
			t.Errorf("DebCompare(%q, %q) = %d, want %d (%s)", test.a, test.b, got, test.want, test.why)
		}
		if got := secure.DebCompare(test.b, test.a); got != -test.want {
			t.Errorf("DebCompare(%q, %q) is not antisymmetric with its inverse (%s)", test.b, test.a, test.why)
		}
	}
}
