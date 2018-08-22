package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	realx509 "crypto/x509"
	"testing"

	"github.com/smallstep/assert"
	"golang.org/x/crypto/ed25519"
)

func TestGenerateJWK(t *testing.T) {
	tests := []struct {
		kty, crv, alg, use, kid string
		size                    int
		expectedAlg             string
		expectedSize            int
		expectedType            interface{}
		ok                      bool
	}{
		{"EC", "", "", "", "", 0, "ES256", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "", "sig", "", 0, "ES256", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-384", "", "sig", "a-kid", 0, "ES384", 384, &ecdsa.PrivateKey{}, true},
		{"EC", "P-521", "ES521", "sig", "a-kid", 0, "ES521", 521, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "", "enc", "a-kid", 0, "ECDH-ES", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "ECDH-ES+A128KW", "enc", "a-kid", 0, "ECDH-ES+A128KW", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "ECDH-ES+A192KW", "enc", "a-kid", 0, "ECDH-ES+A192KW", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "ECDH-ES+A256KW", "enc", "a-kid", 0, "ECDH-ES+A256KW", 256, &ecdsa.PrivateKey{}, true},
		{"RSA", "", "", "", "", 0, "RS256", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "", "", "", 4096, "RS256", 4096, &rsa.PrivateKey{}, true},
		{"RSA", "", "RS384", "sig", "", 1024, "RS384", 1024, &rsa.PrivateKey{}, true},
		{"RSA", "", "RS521", "sig", "a-kid", 1024, "RS521", 1024, &rsa.PrivateKey{}, true},
		{"RSA", "", "", "enc", "a-kid", 1024, "RSA-OAEP-256", 1024, &rsa.PrivateKey{}, true},
		{"RSA", "", "RSA-OAEP-256", "enc", "a-kid", 1024, "RSA-OAEP-256", 1024, &rsa.PrivateKey{}, true},
		{"RSA", "", "RSA1_5", "enc", "a-kid", 1024, "RSA1_5", 1024, &rsa.PrivateKey{}, true},
		{"RSA", "", "RSA-OAEP", "enc", "a-kid", 1024, "RSA-OAEP", 1024, &rsa.PrivateKey{}, true},
		{"OKP", "", "", "", "", 0, "EdDSA", 64, ed25519.PrivateKey{}, true},
		{"OKP", "", "", "", "sig", 0, "EdDSA", 64, ed25519.PrivateKey{}, true},
		{"OKP", "", "", "EdDSA", "sig", 0, "EdDSA", 64, ed25519.PrivateKey{}, true},
		{"oct", "", "", "", "", 0, "HS256", 32, []byte{}, true},
		{"oct", "", "", "sig", "", 0, "HS256", 32, []byte{}, true},
		{"oct", "", "HS384", "sig", "a-kid", 16, "HS384", 16, []byte{}, true},
		{"oct", "", "HS521", "sig", "a-kid", 64, "HS521", 64, []byte{}, true},
		{"oct", "", "", "enc", "a-kid", 64, "A256GCMKW", 64, []byte{}, true},
		{"oct", "", "dir", "enc", "a-kid", 0, "dir", 32, []byte{}, true},
		{"oct", "", "A128KW", "enc", "a-kid", 0, "A128KW", 32, []byte{}, true},
		{"oct", "", "A192KW", "enc", "a-kid", 0, "A192KW", 32, []byte{}, true},
		{"oct", "", "A256KW", "enc", "a-kid", 0, "A256KW", 32, []byte{}, true},
		{"oct", "", "A128GCMKW", "enc", "a-kid", 0, "A128GCMKW", 32, []byte{}, true},
		{"oct", "", "A192GCMKW", "enc", "a-kid", 0, "A192GCMKW", 32, []byte{}, true},
		{"oct", "", "A256GCMKW", "enc", "a-kid", 0, "A256GCMKW", 32, []byte{}, true},
	}

	for _, tc := range tests {
		jwk, err := GenerateJWK(tc.kty, tc.crv, tc.alg, tc.use, tc.kid, tc.size)
		if !tc.ok {
			assert.Error(t, err)
			assert.Nil(t, jwk)
			continue
		}
		assert.NoError(t, err)

		assert.Equals(t, tc.kid, jwk.KeyID)
		assert.Equals(t, tc.expectedAlg, jwk.Algorithm)
		assert.Type(t, tc.expectedType, jwk.Key)

		switch key := jwk.Key.(type) {
		case *ecdsa.PrivateKey:
			switch tc.expectedSize {
			case 256:
				assert.Equals(t, elliptic.P256(), key.Curve)
			case 384:
				assert.Equals(t, elliptic.P384(), key.Curve)
			case 521:
				assert.Equals(t, elliptic.P521(), key.Curve)
			default:
				t.Errorf("unexpected size %d", tc.expectedSize)
			}
		case *rsa.PrivateKey:
			assert.Equals(t, tc.expectedSize, key.N.BitLen())
		case ed25519.PrivateKey:
			assert.Equals(t, tc.expectedSize, len(key))
		case []byte:
			assert.Equals(t, tc.expectedSize, len(key))
		default:
			t.Errorf("unexpected key type %T", key)
		}
	}
}

func TestKeyUsageForCert(t *testing.T) {
	tests := []struct {
		Cert      *realx509.Certificate
		ExpectUse string
		ExpectErr error
	}{
		{
			Cert: &realx509.Certificate{
				KeyUsage: realx509.KeyUsageDigitalSignature,
			},
			ExpectUse: jwksUsageSig,
		},
		{
			Cert: &realx509.Certificate{
				KeyUsage: realx509.KeyUsageDigitalSignature | realx509.KeyUsageContentCommitment,
			},
			ExpectUse: jwksUsageSig,
		},
		{
			Cert: &realx509.Certificate{
				KeyUsage: realx509.KeyUsageDataEncipherment | realx509.KeyUsageKeyAgreement,
			},
			ExpectUse: jwksUsageEnc,
		},
		{
			Cert: &realx509.Certificate{
				KeyUsage: realx509.KeyUsageDataEncipherment,
			},
			ExpectUse: jwksUsageEnc,
		},
		{
			Cert:      &realx509.Certificate{},
			ExpectErr: errNoCertKeyUsage,
		},
		{
			Cert: &realx509.Certificate{
				KeyUsage: realx509.KeyUsageDigitalSignature | realx509.KeyUsageDataEncipherment,
			},
			ExpectErr: errAmbiguousCertKeyUsage,
		},
	}

	for _, tt := range tests {
		use, err := keyUsageForCert(tt.Cert)
		if tt.ExpectErr != nil {
			assert.Equals(t, tt.ExpectErr, err)
		} else {
			assert.Equals(t, tt.ExpectUse, use)
		}
	}
}
