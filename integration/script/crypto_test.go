package script

import (
	"os"
	"path/filepath"
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

func TestCryptoHelp(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/help.txtar"},
	})
}
