package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/pkg/errors"
	"go.step.sm/crypto/x509util"
)

var urlPrefixes = map[string]uint16{
	"tcp://":   443,
	"tls://":   443,
	"https://": 443,
	"smtps://": 465,
	"ldaps://": 636,
}

// getPeerCertificates creates a connection to a remote server and returns the
// list of server certificates.
//
// If the address does not contain a port then default to port 443.
//
// Params
//
//	*addr*:       can be a host (e.g. smallstep.com) or an IP (e.g. 127.0.0.1)
//	*serverName*: use a specific Server Name Indication (e.g. smallstep.com)
//	*roots*:      a file, a directory, or a comma-separated list of files.
//	*insecure*:   do not verify that the server's certificate has been signed by
//	              a trusted root
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
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}
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
