package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
)

const (
	testCRT = `-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIQBvswFbAODY9xtJ/myiuEHzAKBggqhkjOPQQDAjAkMSIw
IAYDVQQDExlTbWFsbHN0ZXAgSW50ZXJtZWRpYXRlIENBMB4XDTE4MTEzMDE5NTkw
OVoXDTE4MTIwMTE5NTkwOVowHjEcMBoGA1UEAxMTaGVsbG8uc21hbGxzdGVwLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIqPQy8roJTMWpEt8NNA1CnRm3l1
wdjH4OrVaH3l2Gp/UW737Wbn4sqSAFahmajuwkfRG5KMh2/+xnCkGuR2fayjge0w
geowDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAdBgNVHQ4EFgQU5bqyXvZaEmtZ3OpZapq7pBIkVvgwHwYDVR0jBBgwFoAUu97P
aFQPfuyKOeew7Hg45WFIAVMwHgYDVR0RBBcwFYITaGVsbG8uc21hbGxzdGVwLmNv
bTBZBgwrBgEEAYKkZMYoQAEESTBHAgEBBBVtYXJpYW5vQHNtYWxsc3RlcC5jb20E
K2pPMzdkdERia3UtUW5hYnM1VlIwWXc2WUZGdjl3ZUExOGRwM2h0dmRFanMwCgYI
KoZIzj0EAwIDSAAwRQIhALKeC2q0HWyHoZobZFK9HQynLbPOOtAK437RaetlX5ty
AiBXQzvaLlDprQu+THj18aDYLnHA//5mdD3HPJV6KmgdDg==
-----END CERTIFICATE-----`
	testCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIHYMIGAAgEAMB4xHDAaBgNVBAMTE2hlbGxvLnNtYWxsc3RlcC5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASKj0MvK6CUzFqRLfDTQNQp0Zt5dcHYx+Dq1Wh9
5dhqf1Fu9+1m5+LKkgBWoZmo7sJH0RuSjIdv/sZwpBrkdn2soAAwCgYIKoZIzj0E
AwIDRwAwRAIgZgz9gdx9inOp6bSX4EkYiUCyLV9xGvabovu5C9UkRr8CIBGBbkp0
l4tesAKoXelsLygJjPuUGRLK+OtdjPBIN1Zo
-----END CERTIFICATE REQUEST-----`
)

func TestGenerateKey_unrecognizedkt(t *testing.T) {
	var failTests = []struct {
		kt       string
		crv      string
		bits     int
		expected string
	}{
		{"shake and bake", "", 2048, "unrecognized key type: shake and bake"},
		{"EC", "P-12", 0, "invalid value for argument crv (crv: 'P-12')"},
	}

	for i, tc := range failTests {
		k, err := GenerateKey(tc.kt, tc.crv, tc.bits)
		if assert.Error(t, err, i) {
			assert.HasPrefix(t, err.Error(), tc.expected)
			assert.Nil(t, k)
		}
	}

	var ecdsaTests = []struct {
		kt  string
		crv string
	}{
		{"EC", "P-256"},
		{"EC", "P-384"},
		{"EC", "P-521"},
	}

	for i, tc := range ecdsaTests {
		k, err := GenerateKey(tc.kt, tc.crv, 0)
		if assert.NoError(t, err, i) {
			_, ok := k.(*ecdsa.PrivateKey)
			assert.True(t, ok, i)
		}
	}

	k, err := GenerateKey("RSA", "", 2048)
	if assert.NoError(t, err) {
		_, ok := k.(*rsa.PrivateKey)
		assert.True(t, ok)
	}
}

func TestExtractKey(t *testing.T) {
	k, err := GenerateKey("RSA", "", 2048)
	assert.FatalError(t, err)
	rsaKey := k.(*rsa.PrivateKey)
	k, err = GenerateKey("EC", "P-256", 0)
	assert.FatalError(t, err)
	ecKey := k.(*ecdsa.PrivateKey)
	k, err = GenerateKey("OKP", "Ed25519", 0)
	assert.FatalError(t, err)
	edKey := k.(ed25519.PrivateKey)
	k, err = GenerateKey("oct", "", 64)
	assert.FatalError(t, err)
	octKey := k.([]byte)

	b, _ := pem.Decode([]byte(testCRT))
	cert, err := x509.ParseCertificate(b.Bytes)
	assert.FatalError(t, err)

	b, _ = pem.Decode([]byte(testCSR))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	assert.FatalError(t, err)

	type args struct {
		in interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"RSA private key", args{rsaKey}, rsaKey, false},
		{"RSA public key", args{rsaKey.Public()}, rsaKey.Public(), false},
		{"EC private key", args{ecKey}, ecKey, false},
		{"EC public key", args{ecKey.Public()}, ecKey.Public(), false},
		{"OKP private key", args{edKey}, edKey, false},
		{"OKP public key", args{edKey.Public()}, edKey.Public(), false},
		{"oct key", args{octKey}, octKey, false},
		{"certificate", args{cert}, cert.PublicKey, false},
		{"csr", args{csr}, csr.PublicKey, false},
		{"fail", args{"fooo"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractKey(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
