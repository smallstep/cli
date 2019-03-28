package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
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
