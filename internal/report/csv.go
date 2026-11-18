package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/rom/qnginxscanner/internal/scanner"
)

func writeCSV(w io.Writer, res *scanner.ScanResult) error {
	cw := csv.NewWriter(w)
	header := []string{
		"host", "port", "scheme", "url", "port_open", "banner",
		"http_status", "server", "powered_by",
		"nginx_verdict", "nginx_confidence", "nginx_variant", "nginx_version",
		"end_of_life", "protocols", "nginx2root", "finding_ids", "vuln_count", "vuln_ids", "max_severity",
		"security_txt", "server_product", "server_version", "behind_proxy", "cdn", "waf",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, t := range res.Targets {
		for _, s := range t.Services {
			row := []string{
				s.Host, fmt.Sprintf("%d", s.Port), s.Scheme, s.URL,
				fmt.Sprintf("%t", s.PortOpen), s.Banner,
			}
			if s.HTTP != nil {
				row = append(row, fmt.Sprintf("%d", s.HTTP.Status), s.HTTP.Server, s.HTTP.PoweredBy)
			} else {
				row = append(row, "", "", "")
			}
			if s.Nginx != nil {
				maxSev := ""
				for _, v := range s.Nginx.Vulnerabilities {
					maxSev = worseSeverity(maxSev, v.Severity)
				}
				findings := make([]string, 0, len(s.Nginx.Findings))
				for _, f := range s.Nginx.Findings {
					maxSev = worseSeverity(maxSev, f.Severity)
					findings = append(findings, f.ID)
				}
				n2r := ""
				if s.Nginx.Nginx2Root != nil {
					n2r = s.Nginx.Nginx2Root.Status
				}
				ids := make([]string, 0, len(s.Nginx.Vulnerabilities))
				for _, v := range s.Nginx.Vulnerabilities {
					ids = append(ids, v.ID)
				}
				row = append(row,
					string(s.Nginx.Verdict), fmt.Sprintf("%d", s.Nginx.Confidence),
					s.Nginx.Variant, s.Nginx.Version, fmt.Sprintf("%t", s.Nginx.EndOfLife),
					strings.Join(s.Nginx.Protocols, "|"), n2r, strings.Join(findings, "|"),
					fmt.Sprintf("%d", len(s.Nginx.Vulnerabilities)),
					strings.Join(ids, "|"), maxSev,
				)
			} else {
				row = append(row, "", "", "", "", "", "", "", "", "0", "", "")
			}
			row = append(row, fmt.Sprintf("%t", s.SecurityTxt != nil && s.SecurityTxt.Present))

			serverProduct, serverVersion := "", ""
			if s.Server != nil {
				serverProduct, serverVersion = s.Server.Product, s.Server.Version
			}
			behindProxy, cdn, waf := "false", "", ""
			if s.Proxy != nil && s.Proxy.Present {
				behindProxy = "true"
				cdn = strings.Join(s.Proxy.CDN, "|")
				waf = strings.Join(s.Proxy.WAF, "|")
			}
			row = append(row, serverProduct, serverVersion, behindProxy, cdn, waf)

			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
