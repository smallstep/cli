package script

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/jose"
)

func TestCryptoJWTCommand(t *testing.T) {
	b, err := os.ReadFile("./../testdata/p256.pem")
	require.NoError(t, err)

	jwk, err := jose.ReadKey("./../testdata/p256.pem")
	require.NoError(t, err)

	now := time.Now()
	c := &jose.Claims{
		Issuer:    "TestIssuer",
		Subject:   "TestSubject",
		Audience:  jose.Audience([]string{"TestAudience"}),
		Expiry:    jose.UnixNumericDate(now.Add(1 * time.Minute).Unix()),
		NotBefore: jose.UnixNumericDate(now.Add(-1 * time.Minute).Unix()),
		IssuedAt:  jose.UnixNumericDate(now.Unix()),
		ID:        "test-id",
	}

	so := new(jose.SignerOptions).WithType("JWT").WithHeader("kid", jwk.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
		Key:       jwk.Key,
	}, so)
	require.NoError(t, err)

	payload := make(map[string]any)
	raw, err := jose.Signed(signer).Claims(c).Claims(payload).CompactSerialize()
	require.NoError(t, err)

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwt.txtar"},
		Setup: func(e *testscript.Env) error {
			err := os.WriteFile(filepath.Join(e.Cd, "p256.pem"), b, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "token.txt"), []byte(raw), 0600)
			require.NoError(t, err)

			return nil
		},
	})
}

func TestCryptoKeyPair(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/keypair.txtar"},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_key_pair": checkKeyPair,
		},
	})
}

func TestCryptoHelp(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/help.txtar"},
	})
}

func keyLength(jwk *jose.JSONWebKey) (int, error) {
	switch key := jwk.Key.(type) {
	case []byte:
		return len(key) * 8, nil
	case *rsa.PrivateKey:
		return key.N.BitLen(), nil
	case *rsa.PublicKey:
		return key.N.BitLen(), nil
	case *ecdsa.PrivateKey:
		return key.Params().BitSize, nil
	case *ecdsa.PublicKey:
		return key.Params().BitSize, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}

func keyCurve(jwk *jose.JSONWebKey) (elliptic.Curve, error) {
	switch key := jwk.Key.(type) {
	case *ecdsa.PrivateKey:
		return key.Curve, nil
	case *ecdsa.PublicKey:
		return key.Curve, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// checkKeyPair checks that the public/private key pair is valid. It performs
// the following checks:
//
//   - Read and parse the JWK public key, validating it's a valid public key
//   - Read and parse the JWK private key, validating it's a valid private key
//   - Compare the public and private key SHA-1 thumbprints to verify they match
//   - The type of the key that was created
//   - For RSA keys, the key size is the expected size
//   - For EC keys, the key curve is the expected curve
func checkKeyPair(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) < 4 {
		ts.Fatalf("expected at least 4 arguments, got %d", len(args))
	}

	pub, err := jose.ParseKey([]byte(ts.ReadFile(args[0])))
	ts.Check(err)
	priv, err := jose.ParseKey([]byte(ts.ReadFile(args[1])), jose.WithPassword([]byte("password")))
	ts.Check(err)

	pubHash, err := pub.Thumbprint(crypto.SHA1)
	ts.Check(err)
	privHash, err := priv.Thumbprint(crypto.SHA1)
	ts.Check(err)

	if !bytes.Equal(pubHash, privHash) {
		ts.Fatalf("%s and %s have different thumbprints", args[0], args[1])
	}

	expectRSA := false
	if s := strings.ToUpper(args[2]); s == "RSA" {
		expectRSA = true
	}

	if expectRSA {
		if !strings.HasPrefix(pub.Algorithm, "RS") {
			ts.Fatalf("expected RSA key type, got %q", pub.Algorithm)
		}

		expectedLength, err := strconv.Atoi(args[3])
		ts.Check(err)

		length, err := keyLength(pub)
		ts.Check(err)

		if length != expectedLength {
			ts.Fatalf("key length mismatch: expected %d, got %d", expectedLength, length)
		}

		return
	}

	if !strings.HasPrefix(pub.Algorithm, "ES") {
		ts.Fatalf("expected EC key type, got %q", pub.Algorithm)
	}

	kc, err := keyCurve(pub)
	ts.Check(err)

	switch crv := strings.ToUpper(args[3]); crv {
	case "P-256":
		if kc != elliptic.P256() {
			ts.Fatalf("expected P-256 curve, got %q", kc)
		}
	case "P-384":
		if kc != elliptic.P384() {
			ts.Fatalf("expected P-384 curve, got %q", kc)
		}
	case "P-521":
		if kc != elliptic.P521() {
			ts.Fatalf("expected P-521 curve, got %q", kc)
		}
	default:
		ts.Fatalf("unknown curve %q", crv)
	}
}
