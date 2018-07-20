package pem

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/smallstep/assert"
	"golang.org/x/crypto/ed25519"
)

type keyType int

const (
	ecdsaPublicKey keyType = iota
	ecdsaPrivateKey
	ed25519PublicKey
	ed25519PrivateKey
	rsaPublicKey
	rsaPrivateKey
)

type testdata struct {
	typ       keyType
	encrypted bool
}

var files = map[string]testdata{
	"testdata/openssl.p256.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p256.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p256.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.p384.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p384.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p384.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.p521.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p521.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p521.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.rsa1024.pem":           {rsaPrivateKey, false},
	"testdata/openssl.rsa1024.pub.pem":       {rsaPublicKey, false},
	"testdata/openssl.rsa1024.enc.pem":       {rsaPrivateKey, true},
	"testdata/openssl.rsa2048.pem":           {rsaPrivateKey, false},
	"testdata/openssl.rsa2048.pub.pem":       {rsaPublicKey, false},
	"testdata/openssl.rsa2048.enc.pem":       {rsaPrivateKey, true},
	"testdata/pkcs8/openssl.ed25519.pem":     {ed25519PrivateKey, false},
	"testdata/pkcs8/openssl.ed25519.pub.pem": {ed25519PublicKey, false},
	"testdata/pkcs8/openssl.ed25519.enc.pem": {ed25519PrivateKey, true},
	"testdata/pkcs8/openssl.p256.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p256.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p256.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.p384.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p384.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p384.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.p521.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p521.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p521.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.rsa2048.pem":     {rsaPrivateKey, false},
	"testdata/pkcs8/openssl.rsa2048.pub.pem": {rsaPublicKey, false},
	"testdata/pkcs8/openssl.rsa2048.enc.pem": {rsaPrivateKey, true},
	"testdata/pkcs8/openssl.rsa4096.pem":     {rsaPrivateKey, false},
	"testdata/pkcs8/openssl.rsa4096.pub.pem": {rsaPublicKey, false},
}

func TestRead(t *testing.T) {
	var err error
	var key interface{}

	for fn, td := range files {
		if td.encrypted {
			key, err = Read(fn, WithPassword([]byte("mypassword")))
		} else {
			key, err = Read(fn)
		}

		assert.NotNil(t, key)
		assert.NoError(t, err)

		switch td.typ {
		case ecdsaPublicKey:
			assert.Type(t, &ecdsa.PublicKey{}, key)
		case ecdsaPrivateKey:
			assert.Type(t, &ecdsa.PrivateKey{}, key)
		case ed25519PublicKey:
			assert.Type(t, ed25519.PublicKey{}, key)
		case ed25519PrivateKey:
			assert.Type(t, ed25519.PrivateKey{}, key)
		case rsaPublicKey:
			assert.Type(t, &rsa.PublicKey{}, key)
		case rsaPrivateKey:
			assert.Type(t, &rsa.PrivateKey{}, key)
		default:
			t.Errorf("type %T not supported", key)
		}

		// Check encrypted against non-encrypted
		if td.encrypted {
			k, err := Read(strings.Replace(fn, ".enc", "", 1))
			assert.NoError(t, err)
			assert.Equals(t, k, key)
		}

		// Check against public
		switch td.typ {
		case ecdsaPrivateKey, ed25519PrivateKey, rsaPrivateKey:
			pub := strings.Replace(fn, ".enc", "", 1)
			pub = strings.Replace(pub, "pem", "pub.pem", 1)

			k, err := Read(pub)
			assert.NoError(t, err)

			if pk, ok := key.(crypto.Signer); ok {
				assert.Equals(t, k, pk.Public())
			} else {
				t.Errorf("key for %s does not satisfies the crypto.PublicKey interface", fn)
			}
		}
	}
}
