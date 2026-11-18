package nginx

import (
	"strconv"
	"strings"
)

// parseVersion extracts major.minor.patch from a version string, tolerating
// suffixes and a fourth component (OpenResty's "1.25.3.1"). Missing components
// default to 0.
func parseVersion(v string) (maj, min, pat int, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, 0, false
	}
	fields := strings.SplitN(v, ".", 4)
	nums := make([]int, 3)
	for i := 0; i < 3 && i < len(fields); i++ {
		nums[i] = leadingInt(fields[i])
	}
	if _, err := strconv.Atoi(trimToDigits(fields[0])); err != nil {
		return 0, 0, 0, false
	}
	return nums[0], nums[1], nums[2], true
}

func leadingInt(s string) int {
	n := 0
	started := false
	for _, r := range s {
		if r < '0' || r > '9' {
			if started {
				break
			}
			continue
		}
		started = true
		n = n*10 + int(r-'0')
	}
	return n
}

func trimToDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			break
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// compareVersion returns -1, 0 or 1 comparing a and b as major.minor.patch.
func compareVersion(a, b string) int {
	am, an, ap, _ := parseVersion(a)
	bm, bn, bp, _ := parseVersion(b)
	switch {
	case am != bm:
		return sign(am - bm)
	case an != bn:
		return sign(an - bn)
	case ap != bp:
		return sign(ap - bp)
	default:
		return 0
	}
}

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

func sameBranch(a, b string) bool {
	am, an, _, aok := parseVersion(a)
	bm, bn, _, bok := parseVersion(b)
	return aok && bok && am == bm && an == bn
}

// CorrelateVulns correlates nginx leads against the built-in catalogue.
func CorrelateVulns(variant, version string) []Vulnerability {
	return DefaultCatalog().Correlate(variant, version)
}
