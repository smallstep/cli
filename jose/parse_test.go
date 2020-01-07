package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/smallstep/assert"
)

const (
	ecdsaPublicKey keyType = iota
	ecdsaPrivateKey
	ed25519PublicKey
	ed25519PrivateKey
	rsaPublicKey
	rsaPrivateKey
	octKey
)

type testdata struct {
	typ       keyType
	encrypted bool
}

var files = map[string]testdata{
	"testdata/oct.json":           {octKey, false},
	"testdata/oct.enc.json":       {octKey, true},
	"testdata/okp.pub.json":       {ed25519PublicKey, false},
	"testdata/okp.priv.json":      {ed25519PrivateKey, false},
	"testdata/okp.enc.priv.json":  {ed25519PrivateKey, true},
	"testdata/p256.pub.json":      {ecdsaPublicKey, false},
	"testdata/p256.priv.json":     {ecdsaPrivateKey, false},
	"testdata/p256.enc.priv.json": {ecdsaPrivateKey, true},
	"testdata/rsa.pub.json":       {rsaPublicKey, false},
	"testdata/rsa.priv.json":      {rsaPrivateKey, false},
	"testdata/rsa.enc.priv.json":  {rsaPrivateKey, true},
}

var pemFiles = map[string]testdata{
	"../crypto/pemutil/testdata/openssl.p256.pem":              {ecdsaPrivateKey, false},
	"../crypto/pemutil/testdata/openssl.p256.pub.pem":          {ecdsaPublicKey, false},
	"../crypto/pemutil/testdata/openssl.p256.enc.pem":          {ecdsaPrivateKey, true},
	"../crypto/pemutil/testdata/openssl.p384.pem":              {ecdsaPrivateKey, false},
	"../crypto/pemutil/testdata/openssl.p384.pub.pem":          {ecdsaPublicKey, false},
	"../crypto/pemutil/testdata/openssl.p384.enc.pem":          {ecdsaPrivateKey, true},
	"../crypto/pemutil/testdata/openssl.p521.pem":              {ecdsaPrivateKey, false},
	"../crypto/pemutil/testdata/openssl.p521.pub.pem":          {ecdsaPublicKey, false},
	"../crypto/pemutil/testdata/openssl.p521.enc.pem":          {ecdsaPrivateKey, true},
	"../crypto/pemutil/testdata/openssl.rsa1024.pem":           {rsaPrivateKey, false},
	"../crypto/pemutil/testdata/openssl.rsa1024.pub.pem":       {rsaPublicKey, false},
	"../crypto/pemutil/testdata/openssl.rsa1024.enc.pem":       {rsaPrivateKey, true},
	"../crypto/pemutil/testdata/openssl.rsa2048.pem":           {rsaPrivateKey, false},
	"../crypto/pemutil/testdata/openssl.rsa2048.pub.pem":       {rsaPublicKey, false},
	"../crypto/pemutil/testdata/openssl.rsa2048.enc.pem":       {rsaPrivateKey, true},
	"../crypto/pemutil/testdata/pkcs8/openssl.ed25519.pem":     {ed25519PrivateKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.ed25519.pub.pem": {ed25519PublicKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.ed25519.enc.pem": {ed25519PrivateKey, true},
	"../crypto/pemutil/testdata/pkcs8/openssl.p256.pem":        {ecdsaPrivateKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.p256.pub.pem":    {ecdsaPublicKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.p256.enc.pem":    {ecdsaPrivateKey, true},
	"../crypto/pemutil/testdata/pkcs8/openssl.p384.pem":        {ecdsaPrivateKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.p384.pub.pem":    {ecdsaPublicKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.p384.enc.pem":    {ecdsaPrivateKey, true},
	"../crypto/pemutil/testdata/pkcs8/openssl.p521.pem":        {ecdsaPrivateKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.p521.pub.pem":    {ecdsaPublicKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.p521.enc.pem":    {ecdsaPrivateKey, true},
	"../crypto/pemutil/testdata/pkcs8/openssl.rsa2048.pem":     {rsaPrivateKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.rsa2048.pub.pem": {rsaPublicKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.rsa2048.enc.pem": {rsaPrivateKey, true},
	"../crypto/pemutil/testdata/pkcs8/openssl.rsa4096.pem":     {rsaPrivateKey, false},
	"../crypto/pemutil/testdata/pkcs8/openssl.rsa4096.pub.pem": {rsaPublicKey, false},
}

func validateParseKey(t *testing.T, fn, pass string, td testdata) {
	var err error
	var jwk *JSONWebKey

	if td.encrypted {
		jwk, err = ParseKey(fn, WithPassword([]byte(pass)))
	} else {
		jwk, err = ParseKey(fn)
	}
	assert.NoError(t, err)

	assert.NoError(t, ValidateJWK(jwk))

	switch td.typ {
	case ecdsaPublicKey:
		assert.Type(t, &ecdsa.PublicKey{}, jwk.Key)
	case ecdsaPrivateKey:
		assert.Type(t, &ecdsa.PrivateKey{}, jwk.Key)
	case ed25519PublicKey:
		assert.Type(t, ed25519.PublicKey{}, jwk.Key)
	case ed25519PrivateKey:
		assert.Type(t, ed25519.PrivateKey{}, jwk.Key)
	case rsaPublicKey:
		assert.Type(t, &rsa.PublicKey{}, jwk.Key)
	case rsaPrivateKey:
		assert.Type(t, &rsa.PrivateKey{}, jwk.Key)
	case octKey:
		assert.Type(t, []byte{}, jwk.Key)
	default:
		t.Errorf("type %T not supported", jwk.Key)
	}

	if jwk.IsPublic() == false && jwk.KeyID != "" {
		hash, err := jwk.Thumbprint(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equals(t, base64.RawURLEncoding.EncodeToString(hash), jwk.KeyID)
	}

	if td.encrypted {
		jwkPriv, err := ParseKey(strings.Replace(fn, ".enc", "", 1))
		assert.NoError(t, err)
		assert.Equals(t, jwkPriv, jwk)
	}
}

func TestParseKey(t *testing.T) {
	for fn, td := range files {
		validateParseKey(t, fn, "password", td)
	}

	for fn, td := range pemFiles {
		validateParseKey(t, fn, "mypassword", td)
	}
}

func TestParseKeyPasswordFile(t *testing.T) {
	jwk, err := ParseKey("testdata/oct.txt", WithAlg("HS256"), WithUse("sig"), WithKid("the-kid"))
	assert.FatalError(t, err)
	assert.Equals(t, []byte("a true random password"), jwk.Key)
	assert.Equals(t, HS256, jwk.Algorithm)
	assert.Equals(t, "sig", jwk.Use)
	assert.Equals(t, "the-kid", jwk.KeyID)
}

func TestParseKeySet(t *testing.T) {
	jwk, err := ParseKeySet("testdata/jwks.json", WithKid("VjIIRw8jzUM58xrVkc4_g9Tfe2MrPPr8GM8Kjijzqus"))
	assert.NoError(t, err)
	assert.Type(t, ed25519.PublicKey{}, jwk.Key)
	assert.Equals(t, "VjIIRw8jzUM58xrVkc4_g9Tfe2MrPPr8GM8Kjijzqus", jwk.KeyID)

	jwk, err = ParseKeySet("testdata/jwks.json", WithKid("V93A-Yh7Bhw1W2E0igFciviJzX4PXPswoVgriehm9Co"))
	assert.NoError(t, err)
	assert.Type(t, &ecdsa.PublicKey{}, jwk.Key)
	assert.Equals(t, "V93A-Yh7Bhw1W2E0igFciviJzX4PXPswoVgriehm9Co", jwk.KeyID)

	jwk, err = ParseKeySet("testdata/jwks.json", WithKid("duplicated"))
	assert.Error(t, err)
	assert.Equals(t, "multiple keys with kid duplicated have been found on testdata/jwks.json", err.Error())
	assert.Nil(t, jwk)

	jwk, err = ParseKeySet("testdata/jwks.json", WithKid("missing"))
	assert.Error(t, err)
	assert.Equals(t, "cannot find key with kid missing on testdata/jwks.json", err.Error())
	assert.Nil(t, jwk)

	jwk, err = ParseKeySet("testdata/empty.json", WithKid("missing"))
	assert.Error(t, err)
	assert.Equals(t, "cannot find key with kid missing on testdata/empty.json", err.Error())
	assert.Nil(t, jwk)
}

func TestGuessJWKAlgorithm(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.FatalError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.FatalError(t, err)
	rsa, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.FatalError(t, err)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.FatalError(t, err)

	tests := []struct {
		jwk      *JSONWebKey
		expected string
	}{
		{&JSONWebKey{Key: []byte{}, Use: ""}, HS256},
		{&JSONWebKey{Key: []byte{}, Use: "sig"}, HS256},
		{&JSONWebKey{Key: []byte{}, Use: "enc"}, "A256GCMKW"},
		{&JSONWebKey{Key: p256, Use: ""}, ES256},
		{&JSONWebKey{Key: p384, Use: "sig"}, ES384},
		{&JSONWebKey{Key: p521, Use: "enc"}, "ECDH-ES"},
		{&JSONWebKey{Key: p256.Public(), Use: ""}, ES256},
		{&JSONWebKey{Key: p384.Public(), Use: "sig"}, ES384},
		{&JSONWebKey{Key: p521.Public(), Use: "enc"}, "ECDH-ES"},
		{&JSONWebKey{Key: rsa, Use: ""}, RS256},
		{&JSONWebKey{Key: rsa, Use: "sig"}, RS256},
		{&JSONWebKey{Key: rsa, Use: "enc"}, "RSA-OAEP-256"},
		{&JSONWebKey{Key: rsa.Public(), Use: ""}, RS256},
		{&JSONWebKey{Key: rsa.Public(), Use: "sig"}, RS256},
		{&JSONWebKey{Key: rsa.Public(), Use: "enc"}, "RSA-OAEP-256"},
		{&JSONWebKey{Key: edPub, Use: ""}, EdDSA},
		{&JSONWebKey{Key: edPub, Use: "sig"}, EdDSA},
		{&JSONWebKey{Key: edPriv, Use: ""}, EdDSA},
		{&JSONWebKey{Key: edPriv, Use: "sig"}, EdDSA},
	}

	// With context
	ctx, err := new(context).apply(WithAlg(HS256))
	assert.NoError(t, err)
	jwk := &JSONWebKey{Key: []byte("password")}
	guessJWKAlgorithm(ctx, jwk)
	assert.Equals(t, HS256, jwk.Algorithm)

	// With algorithm set
	ctx, err = new(context).apply(WithAlg(HS256))
	assert.NoError(t, err)
	jwk = &JSONWebKey{Key: []byte("password"), Algorithm: HS384}
	guessJWKAlgorithm(ctx, jwk)
	assert.Equals(t, HS384, jwk.Algorithm)

	// Defaults
	for _, tc := range tests {
		guessJWKAlgorithm(new(context), tc.jwk)
		assert.Equals(t, tc.expected, tc.jwk.Algorithm)
	}
}
