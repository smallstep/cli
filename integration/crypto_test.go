package integration

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rogpeppe/go-internal/testscript"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
)

func TestCryptoJWKCommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwk-create.txtar"}, // defaults and generic failures
		Setup: func(e *testscript.Env) error {
			return os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_jwk": checkKeyPair,
		},
	})
}

func TestCryptoJWKCreateRSACommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwk-create-rsa.txtar"}, // RSA generation
		Setup: func(e *testscript.Env) error {
			return os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_jwk":                  checkKeyPair,
			"check_jwk_without_password": checkKeyPairWithoutPassword,
		},
	})
}

func TestCryptoJWKCreateECCommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwk-create-ec.txtar"}, // EC generation
		Setup: func(e *testscript.Env) error {
			return os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_jwk":                  checkKeyPair,
			"check_jwk_without_password": checkKeyPairWithoutPassword,
		},
	})
}

func TestCryptoJWKCreateOKPCommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwk-create-okp.txtar"}, // OKP generation
		Setup: func(e *testscript.Env) error {
			return os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_jwk":                  checkKeyPair,
			"check_jwk_without_password": checkKeyPairWithoutPassword,
		},
	})
}

func TestCryptoJWKCreateOctCommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwk-create-oct.txtar"}, // oct generation
		Setup: func(e *testscript.Env) error {
			return os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_jwk":                  checkKeyPair,
			"check_jwk_without_password": checkKeyPairWithoutPassword,
		},
	})
}

func TestCryptoJWTCommand(t *testing.T) {
	p256JWK, p256Bytes := readKey(t, "./testdata/p256.pem") // TODO(hs): can/must we get rid of these, and generate them on start of test?
	rsaJWK, rsaBytes := readKey(t, "./testdata/rsa2048.pem")
	noUseBytes := readBytes(t, "./testdata/jwk-no-use.json")
	noAlgBytes := readBytes(t, "./testdata/jwk-no-alg.json")
	badKeyBytes := readBytes(t, "./testdata/bad-key.json")
	p256PubJSONBytes := readBytes(t, "./testdata/jwk-pGoLJDgF5fgTNnB47SKMnVUzVNdu6MF0.pub.json")
	p256PubPemBytes := readBytes(t, "./testdata/p256.pem.pub")
	twopemsBytes := readBytes(t, "./testdata/twopems.pem")
	badHeaderBytes := readBytes(t, "./testdata/badheader.pem")
	encP256Bytes := readBytes(t, "./testdata/es256-enc.pem")
	jwks, jwksBytes := readKeySet(t, "./testdata/jwks.json")
	ed25519JWK, ed25519JSONBytes := generateJWK(t, "OKP", "Ed25519")

	jwtJSON := readBytes(t, "./testdata/jwt-json-serialization.json")
	jwtFlattenedJSON := readBytes(t, "./testdata/jwt-json-serialization-flattened.json")
	jwtMultiJSON := readBytes(t, "./testdata/jwt-json-serialization-multi.json")

	now := time.Now()
	p256Token := createToken(t, p256JWK, now)
	rsaToken := createToken(t, rsaJWK, now)
	ed25519Token := createToken(t, ed25519JWK, now)
	jwksToken := createToken(t, &jwks.Key("1")[0], now)

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwt-sign.txtar"},
		Setup: func(e *testscript.Env) error {
			// set some additional environment variables required for token creation
			e.Vars = append(e.Vars,
				fmt.Sprintf("NBF=%d", now.Add(-1*time.Minute).Unix()),
				fmt.Sprintf("EXP=%d", now.Add(1*time.Minute).Unix()),
				fmt.Sprintf("IAT=%d", now.Unix()),
				fmt.Sprintf("EXPIRY_IN_THE_PAST=%d", now.Add(-30*time.Second).Unix()),
			)

			// write the (existing) keys to the (temporary) test directory
			err := os.WriteFile(filepath.Join(e.Cd, "p256.pem"), p256Bytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "rsa.pem"), rsaBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "ed25519.json"), ed25519JSONBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "nouse.json"), noUseBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "noalg.json"), noAlgBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "badkey.json"), badKeyBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "p256.pub.json"), p256PubJSONBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "p256.pub.pem"), p256PubPemBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "twopems.pem"), twopemsBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "badheader.pem"), badHeaderBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "encp256.pem"), encP256Bytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "jwks.json"), jwksBytes, 0600)
			require.NoError(t, err)

			return nil
		},
	})

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwt-verify.txtar"},
		Setup: func(e *testscript.Env) error {
			// write the (existing) keys to the (temporary) test directory
			err := os.WriteFile(filepath.Join(e.Cd, "p256.pem"), p256Bytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "p256token.txt"), []byte(p256Token), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "rsa.pem"), rsaBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "rsatoken.txt"), []byte(rsaToken), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "ed25519.json"), ed25519JSONBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "ed25519token.txt"), []byte(ed25519Token), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "jwks.json"), jwksBytes, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "jwkstoken.txt"), []byte(jwksToken), 0600)
			require.NoError(t, err)

			// write fake / invalid tokens to the (temporary) test directory
			invalidSignature := ed25519Token[:len(ed25519Token)-5] + "12345"
			err = os.WriteFile(filepath.Join(e.Cd, "incomplete-signature.txt"), []byte(invalidSignature), 0600)
			require.NoError(t, err)
			parts := strings.Split(ed25519Token, ".")
			err = os.WriteFile(filepath.Join(e.Cd, "invalid-header.txt"), []byte(createFakeToken(t, "foo", parts[1], parts[2])), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "invalid-header-json.txt"), []byte(createFakeToken(t, "[42]", "bar", "deadbeef")), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "invalid-header-changed-attribute.txt"), []byte(createFakeToken(t, `{"kty":"EC","alg":"ES256","xxx":"yyy"}`, parts[1], parts[2])), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "invalid-header-bad-json.txt"), []byte(createFakeToken(t, `{"kty":"EC","alg":"ES256","}`, parts[1], parts[2])), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "invalid-payload.txt"), []byte(createFakeToken(t, parts[0], "foo", parts[2])), 0600)
			require.NoError(t, err)

			// write tokens created by OpenSSL
			exp := now.Add(1 * time.Minute).Unix()
			validOpenSSLToken := createTokenUsingOpenSSL(t, `{"typ": "JWT", "alg": "RS256"}`, fmt.Sprintf(`{"iss": "TestIssuer", "aud": "TestAudience", "exp": %d}`, exp), "./testdata/rsa2048.pem")
			err = os.WriteFile(filepath.Join(e.Cd, "ossltoken.txt"), []byte(validOpenSSLToken), 0600)
			require.NoError(t, err)
			expiredOpenSSLToken := createTokenUsingOpenSSL(t, `{"typ": "JWT", "alg": "RS256"}`, `{"iss": "TestIssuer", "aud": "TestAudience", "exp": 0}`, "./testdata/rsa2048.pem")
			err = os.WriteFile(filepath.Join(e.Cd, "expired-ossltoken.txt"), []byte(expiredOpenSSLToken), 0600)
			require.NoError(t, err)
			noExpiryOpenSSLToken := createTokenUsingOpenSSL(t, `{"typ": "JWT", "alg": "RS256"}`, `{"iss": "TestIssuer", "aud": "TestAudience"}`, "./testdata/rsa2048.pem")
			err = os.WriteFile(filepath.Join(e.Cd, "no-expiry-ossltoken.txt"), []byte(noExpiryOpenSSLToken), 0600)
			require.NoError(t, err)
			zeroNotBeforeOpenSSLToken := createTokenUsingOpenSSL(t, `{"typ": "JWT", "alg": "RS256"}`, `{"iss": "TestIssuer", "aud": "TestAudience", "nbf": 0}`, "./testdata/rsa2048.pem")
			err = os.WriteFile(filepath.Join(e.Cd, "zero-not-before-ossltoken.txt"), []byte(zeroNotBeforeOpenSSLToken), 0600)
			require.NoError(t, err)

			// write data for JSON serialization errors
			err = os.WriteFile(filepath.Join(e.Cd, "jwt-json-serialization.json"), jwtJSON, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "jwt-json-serialization-flattened.json"), jwtFlattenedJSON, 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "jwt-json-serialization-multi.json"), jwtMultiJSON, 0600)
			require.NoError(t, err)

			return nil
		},
	})

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/jwt-inspect.txtar"},
		Setup: func(e *testscript.Env) error {
			err := os.WriteFile(filepath.Join(e.Cd, "token.txt"), []byte(p256Token), 0600)
			require.NoError(t, err)

			return nil
		},
	})
}

func TestCryptoKeyPair(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/keypair.txtar"},
		Setup: func(e *testscript.Env) error {
			return os.WriteFile(filepath.Join(e.Cd, "password.txt"), []byte("password"), 0600)
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_key_pair": checkKeyPair,
		},
	})
}

func TestCryptoOTP(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/otp.txtar"},
		Setup: func(e *testscript.Env) error {
			secret := "UPCTJYT7MUR4RWOUJ3TGTUB43IYCBJ76"
			err := os.WriteFile(filepath.Join(e.Cd, "secret.txt"), []byte(secret), 0600)
			require.NoError(t, err)
			code, err := totp.GenerateCode(secret, time.Now())
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "code.txt"), []byte(code), 0600)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "invalid.txt"), []byte("aaaaaa"), 0600)
			require.NoError(t, err)
			urlSecret := "EW32D2CFTAIRTEAWTRQZZXAITVA4U6K4"
			url := fmt.Sprintf("otpauth://totp/example.com:foo@example.com?algorithm=SHA1&digits=6&issuer=example.com&period=30&secret=%s", urlSecret)
			err = os.WriteFile(filepath.Join(e.Cd, "urlsecret.txt"), []byte(urlSecret), 0600)
			require.NoError(t, err)
			key, err := otp.NewKeyFromURL(url)
			require.NoError(t, err)
			urlCode, err := totp.GenerateCode(key.Secret(), time.Now())
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(e.Cd, "urlcode.txt"), []byte(urlCode), 0600)
			require.NoError(t, err)
			return nil
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_otp": checkOTP,
		},
	})
}

func checkOTP(ts *testscript.TestScript, neg bool, args []string) {
	out := strings.TrimSpace(ts.ReadFile(args[0]))

	length, err := strconv.Atoi(args[1])
	ts.Check(err)

	if out == "" {
		ts.Fatalf("expected OTP not be empty")
	}

	if length != -1 {
		if len(out) != length {
			ts.Fatalf("expected OTP to be %d characters long; got %d", length, len(out))
		}
	}

	if strings.HasPrefix(out, "otpauth://") {
		key, err := otp.NewKeyFromURL(out)
		ts.Check(err)

		switch {
		case key.Type() != "totp":
			ts.Fatalf("expected OTP to be type totp; got %s", key.Type())
		case key.Issuer() != "example.com":
			ts.Fatalf("expected issuer to be example.com; got %s", key.Issuer())
		case key.AccountName() != "foo@example.com":
			ts.Fatalf("expected account name to be foo@example.com; got %s", key.AccountName())
		case len(key.Secret()) != 32:
			ts.Fatalf("expected secret to be 32 bytes; got %d", len(key.Secret()))
		}
	}
}

func TestCryptoHelp(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/help.txtar"},
	})
}

// checkKeyPair checks that the public/private key pair provided as filenames in
// the first and second argument is valid. It always uses the password "password".
// Other validations are delegated to the checkKeyDetails function.
func checkKeyPair(ts *testscript.TestScript, _ bool, args []string) {
	if len(args) < 4 {
		ts.Fatalf("expected at least 4 arguments, got %d", len(args))
	}

	pub, err := jose.ParseKey([]byte(ts.ReadFile(args[0])))
	ts.Check(err)
	priv, err := jose.ParseKey([]byte(ts.ReadFile(args[1])), jose.WithPassword([]byte("password")))
	ts.Check(err)

	checkKeyDetails(ts, pub, priv, args)
}

// checkKeyPair checks that the public/private key pair provided as filenames in
// the first and second argument is valid. It assumes no password is set on the file.
// Other validations are delegated to the checkKeyDetails function.
func checkKeyPairWithoutPassword(ts *testscript.TestScript, _ bool, args []string) {
	if len(args) < 4 {
		ts.Fatalf("expected at least 4 arguments, got %d", len(args))
	}

	pub, err := jose.ParseKey([]byte(ts.ReadFile(args[0])))
	ts.Check(err)
	priv, err := jose.ParseKey([]byte(ts.ReadFile(args[1])))
	ts.Check(err)

	checkKeyDetails(ts, pub, priv, args)
}

// checkKeyDetails checks that the public/private key pair is valid. It performs
// the following checks:
//
//   - Compare the public and private key SHA-1 thumbprints to verify they match
//   - The type of the key that was created
//   - For RSA keys, the key size is the expected size, and using the expected algorithm
//   - For EC keys, the key curve is the expected curve, and using the expected algorithm
//   - For OKP keys, the key curve is the expected curve, and using the expected algorithm
//   - For oct keys, the key parts are of the expected type, and using the expected algorithm
func checkKeyDetails(ts *testscript.TestScript, pub, priv *jose.JSONWebKey, args []string) {
	keyType := strings.ToUpper(args[2])
	if keyType == "OCT" {
		if _, ok := pub.Key.([]byte); !ok {
			ts.Fatalf("expected public key %s to be a byte slice; got %T", args[0], pub.Key)
		}
		if _, ok := priv.Key.([]byte); !ok {
			ts.Fatalf("expected private key %s to be a byte slice; got %T", args[0], pub.Key)
		}
	} else {
		pubHash, err := pub.Thumbprint(crypto.SHA1)
		ts.Check(err)
		privHash, err := priv.Thumbprint(crypto.SHA1)
		ts.Check(err)

		if !bytes.Equal(pubHash, privHash) {
			ts.Fatalf("%s and %s have different thumbprints", args[0], args[1])
		}
	}

	switch {
	case keyType == "RSA":
		if !strings.HasPrefix(pub.Algorithm, "RS") && !strings.HasPrefix(pub.Algorithm, "PS") {
			ts.Fatalf("expected RSA algorithm for RSA key, got %q", pub.Algorithm)
		}

		expectedLength, err := strconv.Atoi(args[3])
		ts.Check(err)

		length, err := keyLength(pub)
		ts.Check(err)

		if length != expectedLength {
			ts.Fatalf("key length mismatch: expected %d, got %d", expectedLength, length)
		}

		if len(args) > 4 {
			expectedAlgorithm := args[4]
			if !strings.EqualFold(pub.Algorithm, expectedAlgorithm) {
				ts.Fatalf("key algorithm mismatch: expected %s, got %s", expectedAlgorithm, pub.Algorithm)
			}
		}

		return
	case keyType == "OKP":
		if !strings.HasPrefix(pub.Algorithm, "EdDSA") {
			ts.Fatalf("expected EC algorithm for EC key, got %q", pub.Algorithm)
		}

		if crv := strings.ToUpper(args[3]); crv != "ED25519" {
			ts.Fatalf("unexpected OKP curve %q", args[3])
		}
	case keyType == "OCT":
		if !strings.HasPrefix(pub.Algorithm, "HS") && !strings.HasPrefix(pub.Algorithm, "A") && pub.Algorithm != "dir" {
			ts.Fatalf("expected oct algorithm for oct key, got %q", pub.Algorithm)
		}

		expectedAlgorithm := args[3]
		if !strings.EqualFold(pub.Algorithm, expectedAlgorithm) {
			ts.Fatalf("key algorithm mismatch: expected %s, got %s", expectedAlgorithm, pub.Algorithm)
		}
	case strings.HasPrefix(keyType, "EC"):
		if !strings.HasPrefix(pub.Algorithm, "ES") && !strings.HasPrefix(pub.Algorithm, "ECDH") {
			ts.Fatalf("expected EC algorithm for EC key, got %q", pub.Algorithm)
		}

		if len(args) > 4 {
			expectedAlgorithm := args[4]
			if !strings.EqualFold(pub.Algorithm, expectedAlgorithm) {
				ts.Fatalf("key algorithm mismatch: expected %s, got %s", expectedAlgorithm, pub.Algorithm)
			}
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
	default:
		ts.Fatalf("unknown key format %q", args[2])
	}
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

func createToken(t *testing.T, jwk *jose.JSONWebKey, now time.Time) string {
	t.Helper()

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

	return raw
}

func readBytes(t *testing.T, file string) []byte {
	t.Helper()

	b, err := os.ReadFile(file)
	require.NoError(t, err)

	return b
}

func readKey(t *testing.T, file string) (*jose.JSONWebKey, []byte) {
	t.Helper()

	b := readBytes(t, file)
	jwk, err := jose.ParseKey(b)
	require.NoError(t, err)

	return jwk, b
}

func readKeySet(t *testing.T, file string) (*gojose.JSONWebKeySet, []byte) {
	t.Helper()

	b := readBytes(t, file)
	var jwks gojose.JSONWebKeySet
	err := json.Unmarshal(b, &jwks)
	require.NoError(t, err)

	return &jwks, b
}

func generateJWK(t *testing.T, kty, crv string) (*jose.JSONWebKey, []byte) {
	t.Helper()

	pk, err := keyutil.GenerateKey(kty, crv, 0)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:   pk,
		KeyID: fmt.Sprintf("kid-%s-%s", kty, crv),
		//Algorithm: string(jose.ES256),
		Use: "sig", // use for signature
	}

	b, err := jwk.MarshalJSON()
	require.NoError(t, err)

	return &jwk, b
}

func createFakeToken(t *testing.T, header, payload, signature string) string {
	t.Helper()

	header = base64.RawURLEncoding.EncodeToString([]byte(header))
	payload = base64.RawURLEncoding.EncodeToString([]byte(payload))
	return strings.Join([]string{header, payload, signature}, ".")
}

func createTokenUsingOpenSSL(t *testing.T, header, payload, key string) string {
	t.Helper()

	cmd := fmt.Sprintf("./openssl-jwt.sh -a RS256 -k %s '%s' '%s'", key, header, payload)
	jwt, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	require.NoError(t, err)
	return string(jwt)
}
