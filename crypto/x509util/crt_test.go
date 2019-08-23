package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"testing"

	"github.com/smallstep/assert"
)

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name string
		fn   string
		want string
	}{
		{"ok", "test_files/ca.crt", "6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := mustParseCertificate(t, tt.fn)
			if got := Fingerprint(cert); got != tt.want {
				t.Errorf("Fingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustParseCertificate(t *testing.T, filename string) *x509.Certificate {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		t.Fatalf("failed to decode PEM in %s", filename)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate in %s: %v", filename, err)
	}
	return cert
}

func TestSplitSANs(t *testing.T) {
	tests := []struct {
		name              string
		sans, dns, emails []string
		ips               []net.IP
	}{
		{name: "empty", sans: []string{}, dns: []string{}, ips: []net.IP{}, emails: []string{}},
		{
			name:   "all-dns",
			sans:   []string{"foo.internal", "bar.internal"},
			dns:    []string{"foo.internal", "bar.internal"},
			ips:    []net.IP{},
			emails: []string{},
		},
		{
			name:   "all-ip",
			sans:   []string{"0.0.0.0", "127.0.0.1"},
			dns:    []string{},
			ips:    []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("127.0.0.1")},
			emails: []string{},
		},
		{
			name:   "all-email",
			sans:   []string{"max@smallstep.com", "mariano@smallstep.com"},
			dns:    []string{},
			ips:    []net.IP{},
			emails: []string{"max@smallstep.com", "mariano@smallstep.com"},
		},
		{
			name:   "mix",
			sans:   []string{"foo.internal", "max@smallstep.com", "mariano@smallstep.com", "1.1.1.1", "bar.internal"},
			dns:    []string{"foo.internal", "bar.internal"},
			ips:    []net.IP{net.ParseIP("1.1.1.1")},
			emails: []string{"max@smallstep.com", "mariano@smallstep.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns, ips, emails := SplitSANs(tt.sans)
			assert.Equals(t, dns, tt.dns)
			assert.Equals(t, ips, tt.ips)
			assert.Equals(t, emails, tt.emails)
		})
	}
}
