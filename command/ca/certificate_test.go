package ca

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/token"
)

// newCertificateContext builds a cli.Context with the certificate command
// flags registered and the given arguments parsed.
func newCertificateContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("certificate", flag.ContinueOnError)
	cmd := certificateCommand()
	for _, f := range cmd.Flags {
		f.Apply(set)
	}
	ctx := cli.NewContext(&cli.App{}, set, nil)
	ctx.Command = cmd
	require.NoError(t, set.Parse(args))
	return ctx
}

// writeTokenFile writes the given content to a file inside dir and returns its
// path.
func writeTokenFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// newJWKToken returns a signed JWK token for the given subject using a
// non-HTTP audience so that certificate issuance fails before any network
// access.
func newJWKToken(t *testing.T, subject string) string {
	t.Helper()
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "", "", 0)
	require.NoError(t, err)
	claims, err := token.NewClaims(
		token.WithSubject(subject),
		token.WithAudience("step-ca://sign"),
		token.WithSHA("test-sha"),
	)
	require.NoError(t, err)
	signed, err := claims.Sign(jose.ES256, jwk.Key)
	require.NoError(t, err)
	return signed
}

// newOIDCToken returns a signed OIDC token.
func newOIDCToken(t *testing.T) string {
	t.Helper()
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "", "", 0)
	require.NoError(t, err)
	claims, err := token.NewClaims(token.WithSubject("user@example.com"))
	require.NoError(t, err)
	signed, err := claims.Sign(jose.ES256, jwk.Key)
	require.NoError(t, err)
	return signed
}

func TestCertificateCommand_tokenFileFlag(t *testing.T) {
	cmd := certificateCommand()

	var found *cli.StringFlag
	for i := range cmd.Flags {
		if f, ok := cmd.Flags[i].(cli.StringFlag); ok && f.Name == "token-file" {
			found = &f
			break
		}
	}
	require.NotNil(t, found, "expected a '--token-file' flag to be registered")
	assert.NotEmpty(t, found.Usage)
	assert.Contains(t, cmd.UsageText, "--token-file")
	assert.Contains(t, cmd.UsageText, "=<file>")
}

func Test_resolveCertificateToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := writeTokenFile(t, dir, "token.txt", "jwt-token")
	emptyPath := writeTokenFile(t, dir, "empty.txt", "")
	spacePath := writeTokenFile(t, dir, "space.txt", "  \n\t\n")
	missingPath := filepath.Join(dir, "missing.txt")

	tests := []struct {
		name       string
		args       []string
		wantTok    string
		wantSource string
		wantErr    string
	}{
		{
			name:       "no external token source",
			args:       []string{"internal.example.com", "cert.crt", "key.key"},
			wantTok:    "",
			wantSource: "",
		},
		{
			name:       "explicit token",
			args:       []string{"--token", "jwt-token", "internal.example.com", "cert.crt", "key.key"},
			wantTok:    "jwt-token",
			wantSource: "token",
		},
		{
			name:       "token file",
			args:       []string{"--token-file", tokenPath, "internal.example.com", "cert.crt", "key.key"},
			wantTok:    "jwt-token",
			wantSource: "token-file",
		},
		{
			name:       "token file with trailing newline",
			args:       []string{"--token-file", writeTokenFile(t, dir, "newline.txt", "jwt-token\n"), "internal.example.com", "cert.crt", "key.key"},
			wantTok:    "jwt-token",
			wantSource: "token-file",
		},
		{
			name:       "token file with surrounding whitespace",
			args:       []string{"--token-file", writeTokenFile(t, dir, "spacey.txt", "  jwt-token  \n"), "internal.example.com", "cert.crt", "key.key"},
			wantTok:    "jwt-token",
			wantSource: "token-file",
		},
		{
			name:    "token and token file",
			args:    []string{"--token", "jwt-token", "--token-file", tokenPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--token' and flag '--token-file' are mutually exclusive",
		},
		{
			name:    "empty token file",
			args:    []string{"--token-file", emptyPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "is empty or contains only whitespace",
		},
		{
			name:    "whitespace-only token file",
			args:    []string{"--token-file", spacePath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "is empty or contains only whitespace",
		},
		{
			name:    "missing token file",
			args:    []string{"--token-file", missingPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: missingPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCertificateContext(t, tt.args...)
			gotTok, gotSource, err := resolveCertificateToken(ctx)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTok, gotTok)
			assert.Equal(t, tt.wantSource, gotSource)
		})
	}
}

func Test_certificateAction_tokenSource(t *testing.T) {
	dir := t.TempDir()
	tok := newJWKToken(t, "internal.example.com")
	tokenPath := writeTokenFile(t, dir, "token.txt", tok)
	emptyPath := writeTokenFile(t, dir, "empty.txt", "")
	missingPath := filepath.Join(dir, "missing.txt")

	tests := []struct {
		name    string
		args    []string
		wantErr string
		exclude []string
	}{
		{
			name:    "token and token file",
			args:    []string{"--token", tok, "--token-file", tokenPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--token' and flag '--token-file' are mutually exclusive",
		},
		{
			name:    "offline and token file",
			args:    []string{"--offline", "--token-file", tokenPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--offline' is incompatible with '--token-file'",
		},
		{
			name:    "offline and token",
			args:    []string{"--offline", "--token", tok, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--offline' is incompatible with '--token'",
		},
		{
			name:    "empty token file",
			args:    []string{"--token-file", emptyPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "is empty or contains only whitespace",
		},
		{
			name:    "missing token file",
			args:    []string{"--token-file", missingPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: missingPath,
		},
		{
			name:    "valid token file reaches the certificate flow",
			args:    []string{"--token-file", tokenPath, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "requires the '--ca-url' flag",
			exclude: []string{"unless", "empty", "mutually exclusive"},
		},
		{
			name:    "valid explicit token reaches the certificate flow",
			args:    []string{"--token", tok, "internal.example.com", "cert.crt", "key.key"},
			wantErr: "requires the '--ca-url' flag",
			exclude: []string{"unless", "empty", "mutually exclusive"},
		},
		{
			name:    "no external token uses automatic generation",
			args:    []string{"internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--ca-url' is required unless the '--token' flag is provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCertificateContext(t, tt.args...)
			err := certificateAction(ctx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			for _, s := range tt.exclude {
				assert.NotContains(t, err.Error(), s)
			}
		})
	}
}

func Test_certificateAction_jwkSAN(t *testing.T) {
	dir := t.TempDir()
	jwkTok := newJWKToken(t, "internal.example.com")
	jwkTokenPath := writeTokenFile(t, dir, "jwk.txt", jwkTok)
	oidcTok := newOIDCToken(t)
	oidcTokenPath := writeTokenFile(t, dir, "oidc.txt", oidcTok)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "JWK token-file and san are mutually exclusive",
			args:    []string{"--token-file", jwkTokenPath, "--san", "internal.example.com", "internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--token-file' and flag '--san' are mutually exclusive",
		},
		{
			name:    "JWK token and san are mutually exclusive",
			args:    []string{"--token", jwkTok, "--san", "internal.example.com", "internal.example.com", "cert.crt", "key.key"},
			wantErr: "flag '--token' and flag '--san' are mutually exclusive",
		},
		{
			name:    "OIDC token-file and san are not mutually exclusive",
			args:    []string{"--token-file", oidcTokenPath, "--san", "internal.example.com", "internal.example.com", "cert.crt", "key.key"},
			wantErr: "requires the '--ca-url' flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCertificateContext(t, tt.args...)
			err := certificateAction(ctx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
