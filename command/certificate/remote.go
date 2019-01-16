package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
)

var urlPrefixes = []string{"https://", "tcp://", "tls://"}

func getPeerCertificates(addr, roots string, insecure bool) ([]*x509.Certificate, error) {
	var (
		err     error
		rootCAs *x509.CertPool
	)
	if roots != "" {
		rootCAs, err = x509util.ReadCertPool(roots)
		if err != nil {
			return nil, errors.Wrapf(err, "failure to load root certificate pool from input path '%s'", roots)
		}
	}
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	tlsConfig := &tls.Config{RootCAs: rootCAs}
	if insecure {
		tlsConfig.InsecureSkipVerify = true
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect")
	}
	conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func trimURLPrefix(url string) (bool, string, string) {
	for _, prefix := range urlPrefixes {
		if strings.HasPrefix(url, prefix) {
			return true, prefix, strings.TrimPrefix(url, prefix)
		}
	}
	return false, "", ""
}

// isURL returns true if the input string is formatted as a URL with one of the
// documented prefixes.
func isURL(str string) bool {
	for _, prefix := range urlPrefixes {
		if strings.HasPrefix(str, prefix) {
			return true
		}
	}
	return false
}
