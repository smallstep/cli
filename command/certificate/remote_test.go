package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func TestTrimURL(t *testing.T) {
	type newTest struct {
		input, host string
		isURL       bool
		err         error
	}
	tests := map[string]newTest{
		"true-http":      {"https://smallstep.com", "smallstep.com:443", true, nil},
		"true-tcp":       {"tcp://smallstep.com:8080", "smallstep.com:8080", true, nil},
		"true-tls":       {"tls://smallstep.com/onboarding", "smallstep.com:443", true, nil},
		"false":          {"./certs/root_ca.crt", "", false, nil},
		"false-err":      {"https://google.com hello", "", false, errors.New("error parsing URL 'https://google.com hello'")},
		"true-http-case": {"hTtPs://sMaLlStEp.cOm", "sMaLlStEp.cOm:443", true, nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			host, isURL, err := trimURL(tc.input)
			assert.Equals(t, tc.host, host)
			assert.Equals(t, tc.isURL, isURL)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestGetPeerCertificateServerName(t *testing.T) {
	host := "smallstep.com"
	serverName := host
	ips, err := net.LookupIP(host)
	if err != nil {
		t.Fatalf("unknown host %s: %s", host, err)
	}
	var addr string
	for i, ip := range ips {
		if ip.To4() != nil {
			addr = ips[i].String()
			break
		}
	}
	if addr == "" {
		assert.FatalError(t, errors.New("could not find ipv4 address for smallstep.com"))
		return
	}

	type newTest struct {
		addr, serverName string
		err              error
	}
	tests := map[string]newTest{
		"sni-disabled-host": {host, "", nil},
		"sni-enabled-host":  {host, serverName, nil},
		"sni-disabled-ip":   {addr, "", errors.New("failed to connect")},
		"sni-enabled-ip":    {addr, serverName, nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := getPeerCertificates(tc.addr, tc.serverName, "", false)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newSelfSignedCA(t *testing.T) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	assert.FatalError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.FatalError(t, err)
	return testCert{cert: cert, key: key}
}

func newSignedCert(t *testing.T, ca testCert, cn string, ips []net.IP) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	assert.FatalError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.FatalError(t, err)
	return testCert{cert: cert, key: key}
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	assert.FatalError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestGetPeerCertificateClientCert(t *testing.T) {
	ca := newSelfSignedCA(t)
	otherCA := newSelfSignedCA(t)
	serverCert := newSignedCert(t, ca, "server", []net.IP{net.ParseIP("127.0.0.1")})
	clientCert := newSignedCert(t, ca, "client", nil)
	mismatchedClientCert := newSignedCert(t, otherCA, "mismatched-client", nil)

	serverTLS, err := tls.X509KeyPair(pemCert(serverCert.cert.Raw), pemECKey(t, serverCert.key))
	assert.FatalError(t, err)
	clientTLSPair, err := tls.X509KeyPair(pemCert(clientCert.cert.Raw), pemECKey(t, clientCert.key))
	assert.FatalError(t, err)
	mismatchedPair, err := tls.X509KeyPair(pemCert(mismatchedClientCert.cert.Raw), pemECKey(t, mismatchedClientCert.key))
	assert.FatalError(t, err)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(ca.cert)
	rootsFile := filepath.Join(t.TempDir(), "roots.pem")
	assert.FatalError(t, os.WriteFile(rootsFile, pemCert(ca.cert.Raw), 0o600))

	// serverHandshake returns the result of the TLS handshake as seen by the
	// server. Because a Go TLS 1.3 client can complete its side of the
	// handshake before receiving a rejection alert, the authoritative check
	// for whether the presented client certificate was accepted is the
	// server-side handshake result.
	serverHandshake := func(t *testing.T, clientCerts []tls.Certificate) ([]*x509.Certificate, error, error) {
		t.Helper()
		l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverTLS},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    rootCAs,
		})
		assert.FatalError(t, err)
		defer l.Close()

		result := make(chan error, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				result <- err
				return
			}
			result <- c.(*tls.Conn).Handshake()
			_ = c.Close()
		}()

		peerCerts, dialErr := getPeerCertificatesWithClientCert(l.Addr().String(), "", rootsFile, false, clientCerts)
		return peerCerts, dialErr, <-result
	}

	t.Run("with-client-cert", func(t *testing.T) {
		peerCerts, dialErr, serverErr := serverHandshake(t, []tls.Certificate{clientTLSPair})
		if dialErr != nil {
			t.Fatalf("expected successful client dial with client cert, got %v", dialErr)
		}
		if serverErr != nil {
			t.Fatalf("expected server to accept client cert, got %v", serverErr)
		}
		if len(peerCerts) == 0 {
			t.Fatal("expected server peer certificates in response")
		}
	})

	t.Run("with-mismatched-client-cert", func(t *testing.T) {
		_, _, serverErr := serverHandshake(t, []tls.Certificate{mismatchedPair})
		if serverErr == nil {
			t.Fatal("expected server to reject a client cert it does not trust")
		}
	})
}
