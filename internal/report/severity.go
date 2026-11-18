package report

import (
	"strings"

	"github.com/rom/qnginxscanner/internal/nginx"
	"github.com/rom/qnginxscanner/internal/scanner"
)

// worseSeverity returns whichever severity string ranks higher.
func worseSeverity(a, b string) string {
	if nginx.SeverityRank(b) > nginx.SeverityRank(a) {
		return strings.ToLower(b)
	}
	if a == "" {
		return ""
	}
	return strings.ToLower(a)
}

// HighestSeverity returns the worst vulnerability-lead or finding severity
// across the scan and its rank (0 when there are none).
func HighestSeverity(res *scanner.ScanResult) (string, int) {
	worst := ""
	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.Nginx == nil {
				continue
			}
			for _, v := range s.Nginx.Vulnerabilities {
				if nginx.SeverityRank(v.Severity) > nginx.SeverityRank(worst) {
					worst = v.Severity
				}
			}
			for _, f := range s.Nginx.Findings {
				if nginx.SeverityRank(f.Severity) > nginx.SeverityRank(worst) {
					worst = f.Severity
				}
			}
		}
	}
	return strings.ToLower(worst), nginx.SeverityRank(worst)
}

// FailOn reports whether the scan meets a severity/EOL gate: "eol" triggers on
// any end-of-life nginx branch; "nginx2root" on any service whose version is in
// the affected range of the NGINX2Root advisories; "low"/"medium"/"high"/
// "critical" trigger when any vulnerability lead or finding is at least that
// severe.
func FailOn(res *scanner.ScanResult, level string) bool {
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "eol" {
		return HasEOL(res)
	}
	if level == "nginx2root" {
		return HasNginx2Root(res)
	}
	threshold := nginx.SeverityRank(level)
	if threshold == 0 {
		return false
	}
	_, rank := HighestSeverity(res)
	return rank >= threshold
}

// HasEOL reports whether any detected service runs an end-of-life nginx branch.
func HasEOL(res *scanner.ScanResult) bool {
	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.Nginx != nil && s.Nginx.EndOfLife {
				return true
			}
		}
	}
	return false
}

// HasNginx2Root reports whether any detected service runs an nginx version in
// the affected range of the NGINX2Root advisories.
func HasNginx2Root(res *scanner.ScanResult) bool {
	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.Nginx != nil && s.Nginx.Nginx2Root != nil && s.Nginx.Nginx2Root.Status == "vulnerable-version" {
				return true
			}
		}
	}
	return false
}
