package secure

// Debian version ordering, implemented natively rather than by shelling out to
// `dpkg --compare-versions`. Two reasons: ValidateVersions is exercised through
// runner.OutputFn stubs in tests, and adding a second external call would mean
// every existing stub had to answer it; and the comparison is pure logic that
// deserves to be unit-testable without a subprocess.
//
// Follows deb-version(7): [epoch:]upstream[-revision], where each part is
// compared by alternating non-digit and digit runs. Within a non-digit run the
// order is `~` < end-of-part < letters < everything else.

import (
	"strconv"
	"strings"
)

// debOrder ranks a single byte for the non-digit comparison pass. Mirrors
// dpkg's own order() so that, notably, `~` sorts before the end of a part —
// which is what makes 1.0~rc1 older than 1.0.
func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// debCompareParts compares one upstream or revision part.
func debCompareParts(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Non-digit run.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = debOrder(a[i])
			}
			if j < len(b) {
				bc = debOrder(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		// Digit run: leading zeros are insignificant, compare numerically.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		na, nb := 0, 0
		for i+na < len(a) && isDigit(a[i+na]) {
			na++
		}
		for j+nb < len(b) && isDigit(b[j+nb]) {
			nb++
		}
		if na != nb {
			return sign(na - nb)
		}
		if na > 0 {
			if c := strings.Compare(a[i:i+na], b[j:j+nb]); c != 0 {
				return c
			}
		}
		i += na
		j += nb
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// splitDebVersion separates [epoch:]upstream[-revision].
func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i >= 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			epoch = n
			v = v[i+1:]
		}
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	} else {
		upstream, revision = v, ""
	}
	return epoch, upstream, revision
}

// DebCompare returns -1, 0 or 1 as a sorts before, equal to, or after b.
func DebCompare(a, b string) int {
	ae, au, ar := splitDebVersion(a)
	be, bu, br := splitDebVersion(b)
	if ae != be {
		return sign(ae - be)
	}
	if c := debCompareParts(au, bu); c != 0 {
		return c
	}
	return debCompareParts(ar, br)
}
