package cautils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/token"
)

func TestIssuerValidityOfflineWarnings(t *testing.T) {
	mini, err := minica.New(minica.WithName("offline warning test"))
	require.NoError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	publicJWK := jwk.Public()
	cfg := &config.Config{
		DNSNames: []string{"127.0.0.1"},
		AuthorityConfig: &config.AuthConfig{
			DisableIssuedAtCheck: true,
			Provisioners: provisioner.List{&provisioner.JWK{
				Type: "JWK", Name: "offline", Key: &publicJWK,
				Claims: &provisioner.Claims{MaxTLSDur: &provisioner.Duration{Duration: 72 * time.Hour}},
			}},
		},
	}
	selectedIssuer := mini.Intermediate
	auth, err := authority.NewEmbedded(authority.WithConfig(cfg), authority.WithX509RootCerts(mini.Root),
		authority.WithX509SignerFunc(func() ([]*x509.Certificate, crypto.Signer, error) {
			return []*x509.Certificate{selectedIssuer}, mini.Signer, nil
		}), authority.WithX509IntermediateCerts(mini.Intermediate), authority.WithQuietInit())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auth.Shutdown()) })
	client := &OfflineCA{authority: auth, config: *cfg}
	generator := NewTokenGenerator(jwk.KeyID, "offline", "https://127.0.0.1/sign", "", time.Time{}, time.Time{}, jwk)
	newRequest := func(expiry time.Time) (*api.SignRequest, any) {
		ott, err := generator.SignToken("offline.example", []string{"offline.example"})
		require.NoError(t, err)
		request, key, err := ca.CreateSignRequest(ott)
		require.NoError(t, err)
		request.NotAfter = api.NewTimeDuration(expiry)
		return request, key
	}
	now := time.Now().UTC().Truncate(time.Second)
	request, oldKey := newRequest(now.Add(18 * time.Hour))
	old, err := client.Sign(request)
	require.NoError(t, err)
	require.Empty(t, old.Warnings)
	issuerTemplate := *mini.Intermediate
	issuerTemplate.NotAfter = now.Add(12 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, mini.Root, mini.Signer.Public(), mini.RootSigner)
	require.NoError(t, err)
	selectedIssuer, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	var logs bytes.Buffer
	previousLogger := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousLogger) })
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{old.ServerPEM.Raw, old.CaPEM.Raw}, PrivateKey: oldKey}},
	}}
	for _, operation := range []string{"sign", "renew", "token-renew", "rekey"} {
		t.Run(operation, func(t *testing.T) {
			var response *api.SignResponse
			expectedKey := old.ServerPEM.PublicKey
			var err error
			switch operation {
			case "sign":
				request, key := newRequest(now.Add(36 * time.Hour))
				expectedKey = key.(crypto.Signer).Public()
				response, err = client.Sign(request)
			case "renew":
				response, err = client.Renew(transport)
			case "token-renew":
				claims, tokenErr := token.NewClaims(
					token.WithAudience(client.GetCaURL()+"/renew"),
					token.WithIssuer("step-ca-client/1.0"),
					token.WithSubject(old.ServerPEM.Subject.CommonName),
					token.WithX5CInsecureCerts([]*x509.Certificate{old.ServerPEM.Certificate, old.CaPEM.Certificate}, oldKey),
				)
				require.NoError(t, tokenErr)
				ott, tokenErr := claims.Sign("", oldKey)
				require.NoError(t, tokenErr)
				response, err = client.RenewWithToken(ott)
			case "rekey":
				key, keyErr := keyutil.GenerateDefaultSigner()
				require.NoError(t, keyErr)
				expectedKey = key.Public()
				csrDER, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
				require.NoError(t, csrErr)
				csr, parseErr := x509.ParseCertificateRequest(csrDER)
				require.NoError(t, parseErr)
				response, err = client.Rekey(&api.RekeyRequest{CsrPEM: api.NewCertificateRequest(csr)}, transport)
			}
			require.NoError(t, err)
			require.True(t, keyutil.Equal(expectedKey, response.ServerPEM.PublicKey))
			require.Equal(t, selectedIssuer.NotAfter, response.ServerPEM.NotAfter)
			require.NoError(t, response.ServerPEM.CheckSignatureFrom(selectedIssuer))
			require.Len(t, response.Warnings, 1)
			warning := response.Warnings[0]
			require.Equal(t, "issuer_validity_truncated", warning.Code)
			require.Equal(t, response.ServerPEM.NotAfter, warning.EffectiveNotAfter)
			require.Equal(t, selectedIssuer.NotAfter, warning.LimitingCertificate.NotAfter)
			require.Greater(t, warning.RequestedNotAfter.Unix(), warning.EffectiveNotAfter.Unix())
			// The warning belongs to this operation, not the singleton OfflineCA.
			request, _ := newRequest(now.Add(time.Hour))
			uncapped, err := client.Sign(request)
			require.NoError(t, err)
			require.Empty(t, uncapped.Warnings)
		})
	}
	require.NotContains(t, logs.String(), "WARNING:")

	t.Run("failed operation has no success warning", func(t *testing.T) {
		request, _ := newRequest(now.Add(100 * time.Hour))
		response, err := client.Sign(request)
		require.Error(t, err)
		require.Nil(t, response)
		require.NotContains(t, logs.String(), "WARNING:")
	})
}
