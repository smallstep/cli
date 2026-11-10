package cautils

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
)

func acmeFlagsContext(t *testing.T, values map[string]string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	for _, name := range []string{"kty", "curve", "not-before", "not-after", "eab-key-id", "eab-hmac-key-file", "remote-attestation-plugin", "remote-attestation-audience"} {
		set.String(name, values[name], "")
	}
	set.Int("size", 0, "")
	set.Bool("insecure", false, "")
	return cli.NewContext(cli.NewApp(), set, nil)
}

func TestNewRemoteAttestationOrder(t *testing.T) {
	af := &acmeFlow{ctx: acmeFlagsContext(t, nil), subject: "the-hint", sans: []string{"the-hint"}}

	order, err := af.newRemoteAttestationOrder()
	require.NoError(t, err)

	assert.Equal(t, []acme.Identifier{{Type: acme.RemoteAttestation, Value: "the-hint"}}, order.Identifiers,
		"a name in the order would need a challenge of its own and never finalize")

	require.NotNil(t, af.csr, "the evidence binds the key, so the request exists before the challenge")
	assert.NoError(t, af.csr.CheckSignature())
	assert.Empty(t, af.csr.Subject.String())
	assert.Empty(t, af.csr.DNSNames)
	assert.Empty(t, af.csr.IPAddresses)
	assert.Empty(t, af.csr.URIs)
	assert.Empty(t, af.csr.EmailAddresses)

	signer, ok := af.priv.(crypto.Signer)
	require.True(t, ok, "the certificate's key is written to the key file")
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, af.csr.RawSubjectPublicKeyInfo, spki)
}

func TestNewRemoteAttestationOrder_badTime(t *testing.T) {
	af := &acmeFlow{ctx: acmeFlagsContext(t, map[string]string{"not-after": "not a time"}), subject: "the-hint"}
	_, err := af.newRemoteAttestationOrder()
	assert.Error(t, err)
	assert.Nil(t, af.csr)
}

// newACMEClientForOption applies op as a client would. The endpoint refuses the
// connection, so an option that is accepted fails later with a network error.
func newACMEClientForOption(op ca.ClientOption) (*ca.ACMEClient, error) {
	return ca.NewACMEClient("http://127.0.0.1:0", nil, op)
}

func TestGetExternalAccountBindingOption(t *testing.T) {
	hmacKey := []byte{0xfb, 0xff, 0xfe, 0x01, 0x02, 0x03}
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "base64url, as step-ca prints it", content: base64.RawURLEncoding.EncodeToString(hmacKey)},
		{name: "standard base64", content: base64.RawStdEncoding.EncodeToString(hmacKey)},
		{name: "padding and a newline", content: base64.URLEncoding.EncodeToString(hmacKey[:4]) + "\n"},
		{name: "not base64", content: "!!!", wantErr: "error decoding the HMAC key"},
		{name: "empty", content: "", wantErr: "an external account binding needs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "eab.key")
			require.NoError(t, os.WriteFile(file, []byte(tt.content), 0o600))
			af := &acmeFlow{ctx: acmeFlagsContext(t, map[string]string{"eab-key-id": "key-id", "eab-hmac-key-file": file})}

			op, err := af.getExternalAccountBindingOption()
			if err == nil {
				// The option itself refuses an empty key when the client applies it.
				_, err = newACMEClientForOption(op)
			}
			if tt.wantErr == "" {
				if err != nil {
					assert.NotContains(t, err.Error(), "external account binding needs")
					assert.NotContains(t, err.Error(), "error decoding")
				}
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestGetExternalAccountBindingOption_noFile(t *testing.T) {
	af := &acmeFlow{ctx: acmeFlagsContext(t, map[string]string{
		"eab-key-id": "key-id", "eab-hmac-key-file": filepath.Join(t.TempDir(), "missing"),
	})}
	_, err := af.getExternalAccountBindingOption()
	assert.Error(t, err)
}

func TestRemoteAttestationArgs(t *testing.T) {
	const (
		directory = "https://ca.example.com/acme/pool/directory"
		keyAuth   = "nonce.thumbprint"
	)
	tests := []struct {
		name         string
		audience     string
		wantAudience string
	}{
		{name: "the directory by default", wantAudience: directory},
		{name: "the audience given", audience: "https://ca.example.com/attested", wantAudience: "https://ca.example.com/attested"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := acmeFlagsContext(t, map[string]string{"remote-attestation-audience": tt.audience})
			af := &acmeFlow{ctx: ctx, subject: "the-hint", acmeDir: directory}
			_, err := af.newRemoteAttestationOrder()
			require.NoError(t, err)

			assert.Equal(t, []string{
				"attest",
				"--binding", acme.RemoteAttestationBinding(keyAuth, af.csr),
				"--audience", tt.wantAudience,
			}, remoteAttestationArgs(ctx, af, keyAuth))
		})
	}
}

func TestDoRemoteAttestation_noFreshnessNonce(t *testing.T) {
	err := doRemoteAttestation(acmeFlagsContext(t, nil), nil, &acme.Challenge{URL: "https://ca/challenge"}, "the-hint", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no freshness nonce")
}
