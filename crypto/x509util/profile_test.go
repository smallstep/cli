package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func mustParseRSAKey(t *testing.T, filename string) *rsa.PrivateKey {
	t.Helper()

	b, err := ioutil.ReadFile("test_files/noPasscodeCa.key")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("error decoding %s", filename)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func Test_base_CreateCertificate_KeyEncipherment(t *testing.T) {
	// Issuer
	iss := mustParseCertificate(t, "test_files/noPasscodeCa.crt")
	issPriv := mustParseRSAKey(t, "test_files/noPasscodeCa.key")

	mustCreateLeaf := func(key interface{}) Profile {
		p, err := NewLeafProfile("test.smallstep.com", iss, issPriv, WithPublicKey(key))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Keys and certs
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaProfile := mustCreateLeaf(ecdsaKey.Public())

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaProfile := mustCreateLeaf(rsaKey.Public())

	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Profile := mustCreateLeaf(ed25519PubKey)

	tests := []struct {
		name                string
		profile             Profile
		wantKeyEncipherment bool
	}{
		{"ecdsa", ecdsaProfile, false},
		{"rsa", rsaProfile, true},
		{"ed25519", ed25519Profile, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.profile.CreateCertificate()
			if err != nil {
				t.Errorf("base.CreateCertificate() error = %v", err)
				return
			}
			cert, err := x509.ParseCertificate(got)
			if err != nil {
				t.Errorf("error parsing certificate: %v", err)
			} else {
				ku := cert.KeyUsage & x509.KeyUsageKeyEncipherment
				switch {
				case tt.wantKeyEncipherment && ku == 0:
					t.Errorf("base.CreateCertificate() keyUsage = %x, want %x", cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
				case !tt.wantKeyEncipherment && ku != 0:
					t.Errorf("base.CreateCertificate() keyUsage = %x, want %x", cert.KeyUsage, x509.KeyUsageDigitalSignature)
				}
			}
		})
	}
}
