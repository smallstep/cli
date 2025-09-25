package certificate

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.step.sm/crypto/x509util"
)

var urlPrefixes = map[string]uint16{
	"tcp://":   443,
	"tls://":   443,
	"https://": 443,
	"smtps://": 465,
	"ldaps://": 636,
	"smtp://":  25,  // SMTP with StartTLS
	"imap://":  143, // IMAP with StartTLS
	"pop3://":  110, // POP3 with StartTLS
	"ftp://":   21,  // FTP with StartTLS
}

// getPeerCertificates creates a connection to a remote server and returns the
// list of server certificates. This is the original function signature for backward compatibility.
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
	return getPeerCertificatesWithOptions(addr, serverName, roots, insecure, false, "")
}

// getPeerCertificatesWithOptions creates a connection to a remote server and returns the
// list of server certificates with StartTLS support.
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
//	*startTLS*:   use StartTLS to upgrade plaintext connection to TLS
//	*originalURL*: the original URL to determine protocol for StartTLS
func getPeerCertificatesWithOptions(addr, serverName, roots string, insecure, startTLS bool, originalURL string) ([]*x509.Certificate, error) {
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

	if startTLS {
		return getPeerCertificatesWithStartTLS(addr, tlsConfig, originalURL)
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect")
	}
	conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

// getPeerCertificatesWithStartTLS handles StartTLS negotiation for various protocols
func getPeerCertificatesWithStartTLS(addr string, tlsConfig *tls.Config, originalURL string) ([]*x509.Certificate, error) {
	// Determine protocol from original URL
	protocol := ""
	urlLower := strings.ToLower(originalURL)
	switch {
	case strings.HasPrefix(urlLower, "smtp://"):
		protocol = "smtp"
	case strings.HasPrefix(urlLower, "imap://"):
		protocol = "imap"
	case strings.HasPrefix(urlLower, "pop3://"):
		protocol = "pop3"
	case strings.HasPrefix(urlLower, "ftp://"):
		protocol = "ftp"
	default:
		return nil, errors.New("StartTLS is only supported for smtp://, imap://, pop3://, and ftp:// URLs")
	}

	// Create plaintext connection
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s", addr)
	}
	defer conn.Close()

	// Set connection timeouts
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Perform StartTLS negotiation based on protocol
	switch protocol {
	case "smtp":
		err = startTLSSMTP(conn)
	case "imap":
		err = startTLSIMAP(conn)
	case "pop3":
		err = startTLSPOP3(conn)
	case "ftp":
		err = startTLSFTP(conn)
	default:
		return nil, errors.Errorf("unsupported StartTLS protocol: %s", protocol)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "StartTLS negotiation failed for %s", protocol)
	}

	// Upgrade to TLS connection
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, errors.Wrapf(err, "TLS handshake failed")
	}

	return tlsConn.ConnectionState().PeerCertificates, nil
}

// startTLSSMTP negotiates SMTP StartTLS
func startTLSSMTP(conn net.Conn) error {
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	// Read initial greeting
	if !scanner.Scan() {
		return errors.New("failed to read SMTP greeting")
	}
	if !strings.HasPrefix(scanner.Text(), "220") {
		return errors.Errorf("unexpected SMTP greeting: %s", scanner.Text())
	}

	// Send EHLO command
	_, err := writer.WriteString("EHLO client\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send EHLO")
	}
	writer.Flush()

	// Read EHLO response and check for STARTTLS capability
	startTLSSupported := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250-STARTTLS") || strings.HasPrefix(line, "250 STARTTLS") {
			startTLSSupported = true
		}
		if strings.HasPrefix(line, "250 ") { // Last line of multi-line response
			break
		}
	}

	if !startTLSSupported {
		return errors.New("server does not support STARTTLS")
	}

	// Send STARTTLS command
	_, err = writer.WriteString("STARTTLS\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send STARTTLS")
	}
	writer.Flush()

	// Read STARTTLS response
	if !scanner.Scan() {
		return errors.New("failed to read STARTTLS response")
	}
	if !strings.HasPrefix(scanner.Text(), "220") {
		return errors.Errorf("STARTTLS failed: %s", scanner.Text())
	}

	return nil
}

// startTLSIMAP negotiates IMAP StartTLS
func startTLSIMAP(conn net.Conn) error {
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	// Read initial greeting
	if !scanner.Scan() {
		return errors.New("failed to read IMAP greeting")
	}
	if !strings.HasPrefix(scanner.Text(), "* OK") {
		return errors.Errorf("unexpected IMAP greeting: %s", scanner.Text())
	}

	// Send CAPABILITY command to check for STARTTLS
	_, err := writer.WriteString("a001 CAPABILITY\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send CAPABILITY")
	}
	writer.Flush()

	// Read CAPABILITY response
	startTLSSupported := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "STARTTLS") {
			startTLSSupported = true
		}
		if strings.HasPrefix(line, "a001 OK") {
			break
		}
	}

	if !startTLSSupported {
		return errors.New("server does not support STARTTLS")
	}

	// Send STARTTLS command
	_, err = writer.WriteString("a002 STARTTLS\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send STARTTLS")
	}
	writer.Flush()

	// Read STARTTLS response
	if !scanner.Scan() {
		return errors.New("failed to read STARTTLS response")
	}
	if !strings.HasPrefix(scanner.Text(), "a002 OK") {
		return errors.Errorf("STARTTLS failed: %s", scanner.Text())
	}

	return nil
}

// startTLSPOP3 negotiates POP3 StartTLS
func startTLSPOP3(conn net.Conn) error {
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	// Read initial greeting
	if !scanner.Scan() {
		return errors.New("failed to read POP3 greeting")
	}
	if !strings.HasPrefix(scanner.Text(), "+OK") {
		return errors.Errorf("unexpected POP3 greeting: %s", scanner.Text())
	}

	// Send CAPA command to check capabilities
	_, err := writer.WriteString("CAPA\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send CAPA")
	}
	writer.Flush()

	// Read CAPA response
	if !scanner.Scan() {
		return errors.New("failed to read CAPA response")
	}
	if !strings.HasPrefix(scanner.Text(), "+OK") {
		return errors.Errorf("CAPA command failed: %s", scanner.Text())
	}

	// Check for STLS capability
	startTLSSupported := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "." {
			break
		}
		if strings.Contains(line, "STLS") {
			startTLSSupported = true
		}
	}

	if !startTLSSupported {
		return errors.New("server does not support STLS")
	}

	// Send STLS command
	_, err = writer.WriteString("STLS\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send STLS")
	}
	writer.Flush()

	// Read STLS response
	if !scanner.Scan() {
		return errors.New("failed to read STLS response")
	}
	if !strings.HasPrefix(scanner.Text(), "+OK") {
		return errors.Errorf("STLS failed: %s", scanner.Text())
	}

	return nil
}

// startTLSFTP negotiates FTP StartTLS
func startTLSFTP(conn net.Conn) error {
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	// Read initial greeting
	if !scanner.Scan() {
		return errors.New("failed to read FTP greeting")
	}
	if !strings.HasPrefix(scanner.Text(), "220") {
		return errors.Errorf("unexpected FTP greeting: %s", scanner.Text())
	}

	// Send AUTH TLS command
	_, err := writer.WriteString("AUTH TLS\r\n")
	if err != nil {
		return errors.Wrap(err, "failed to send AUTH TLS")
	}
	writer.Flush()

	// Read AUTH TLS response
	if !scanner.Scan() {
		return errors.New("failed to read AUTH TLS response")
	}
	if !strings.HasPrefix(scanner.Text(), "234") {
		return errors.Errorf("AUTH TLS failed: %s", scanner.Text())
	}

	return nil
}

// trimURL returns the host[:port] if the input is a URL, otherwise returns an
// empty string (and 'isURL:false').
//
// If the URL is valid and no port is specified, the default port determined
// by the URL prefix is used.
//
// Examples:
// trimURL("https://smallstep.com/onboarding") -> "smallstep.com:443", true, nil
// trimURL("https://ca.smallSTEP.com:8080") -> "ca.smallSTEP.com:8080", true, nil
// trimURL("./certs/root_ca.crt") -> "", false, nil
// trimURL("hTtPs://sMaLlStEp.cOm") -> "sMaLlStEp.cOm:443", true, nil
// trimURL("hTtPs://sMaLlStEp.cOm hello") -> "", false, err{"invalid url"}
func trimURL(ref string) (string, bool, error) {
	tmp := strings.ToLower(ref)
	for prefix := range urlPrefixes {
		if strings.HasPrefix(tmp, prefix) {
			u, err := url.Parse(ref)
			if err != nil {
				return "", false, errors.Wrapf(err, "error parsing URL '%s'", ref)
			}
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				port := strconv.FormatUint(uint64(urlPrefixes[prefix]), 10)
				u.Host = net.JoinHostPort(u.Host, port)
			}
			return u.Host, true, nil
		}
	}
	return "", false, nil
}
