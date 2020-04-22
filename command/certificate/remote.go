package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
)

var urlPrefixes = []string{"https://", "tcp://", "tls://"}

// getPeerCertificates creates a connection to a remote server and returns the
// list of server certificates.
//
// If the address does not contain a port then default to port 443.
//
// Params
//   *addr*:     e.g. smallstep.com
//   *roots*:    a file, a directory, or a comma-separated list of files.
//   *insecure*: do not verify that the server's certificate has been signed by
//               a trusted root
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

// trimURL returns the url split into prefix and suffix and a bool which
// tells if the input string had a recognizable URL prefix.
//
// Examples:
// trimURL("https://smallstep.com") -> "https://", "smallstep.com", true
// trimURL("./certs/root_ca.crt") -> "", "", false
// trimURL("hTtPs://sMaLlStEp.cOm") -> "hTtPs://", "sMaLlStEp.cOm", true
func trimURL(url string) (string, string, bool) {
	tmp := strings.ToLower(url)
	for _, prefix := range urlPrefixes {
		if strings.HasPrefix(tmp, prefix) {
			return url[:len(prefix)], strings.TrimSuffix(url[len(prefix):], "/"), true
		}
	}
	return "", "", false
}
