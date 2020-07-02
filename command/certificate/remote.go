package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
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
//   *addr*:       can be a host (e.g. smallstep.com) or an IP (e.g. 127.0.0.1)
//   *serverName*: use a specific Server Name Indication (e.g. smallstep.com)
//   *roots*:      a file, a directory, or a comma-separated list of files.
//   *insecure*:   do not verify that the server's certificate has been signed by
//                 a trusted root
func getPeerCertificates(addr, serverName, roots string, insecure bool) ([]*x509.Certificate, error) {
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
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	tlsConfig := &tls.Config{RootCAs: rootCAs}
	if insecure {
		tlsConfig.InsecureSkipVerify = true
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect")
	}
	conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

// trimURL returns the host[:port] if the input is a URL, otherwise returns an
// empty string (and 'isURL:false').
//
// Examples:
// trimURL("https://smallstep.com/onbaording") -> "smallstep.com", true, nil
// trimURL("https://ca.smallSTEP.com:8080") -> "ca.smallSTEP.com:8080", true, nil
// trimURL("./certs/root_ca.crt") -> "", false, nil
// trimURL("hTtPs://sMaLlStEp.cOm") -> "sMaLlStEp.cOm", true, nil
// trimURL("hTtPs://sMaLlStEp.cOm hello") -> "", false, err{"invalid url"}
func trimURL(ref string) (string, bool, error) {
	tmp := strings.ToLower(ref)
	for _, prefix := range urlPrefixes {
		if strings.HasPrefix(tmp, prefix) {
			u, err := url.Parse(ref)
			if err != nil {
				return "", false, errors.Wrapf(err, "error parsing URL '%s'", ref)
			}
			return u.Host, true, nil
		}
	}
	return "", false, nil
}
