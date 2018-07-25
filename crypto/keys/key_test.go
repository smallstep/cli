package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/smallstep/assert"
)

func Test_GenerateKey_unrecognizedkt(t *testing.T) {
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
