package sansutils

import (
	"net"
	"net/url"

	"github.com/smallstep/cli/crypto/x509util"
)

// Split unifies the SAN collections passed as arguments and returns a list
// of DNS names, a list of IP addresses, and a list of emails.
func Split(args ...[]string) (dnsNames []string, ipAddresses []net.IP, email []string, uris []*url.URL) {
	m := make(map[string]bool)
	var unique []string
	for _, sans := range args {
		for _, san := range sans {
			if ok := m[san]; !ok && san != "" {
				m[san] = true
				unique = append(unique, san)
			}
		}
	}
	return x509util.SplitSANs(unique)
}
