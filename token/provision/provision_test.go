package provision

import (
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/stretchr/testify/assert"
)

func withFixedTime(tok *Token, t time.Time) {
	if tok == nil {
		return
	}
	tok.claims.IssuedAt = jose.NewNumericDate(t)
	tok.claims.NotBefore = jose.NewNumericDate(t)
	tok.claims.Expiry = jose.NewNumericDate(t.Add(5 * time.Minute))
}

func TestNew(t *testing.T) {
	type args struct {
		subject string
		opts    []token.Options
	}

	now := time.Now()
	want := &Token{
		claims: token.DefaultClaims(),
	}
	wantWithOptions := &Token{
		claims: token.DefaultClaims(),
	}

	want.claims.Subject = "test.domain"
	wantWithOptions.claims.Subject = "test.domain"
	wantWithOptions.claims.Issuer = "new-issuer"
	wantWithOptions.claims.ExtraClaims = map[string]interface{}{"sha": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"}

	tests := []struct {
		name    string
		args    args
		want    *Token
		wantErr bool
	}{
		{"ok", args{"test.domain", nil}, want, false},
		{"ok empty options", args{"test.domain", []token.Options{}}, want, false},
		{"ok with options", args{"test.domain", []token.Options{token.WithIssuer("new-issuer"), token.WithClaim("sha", "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}, wantWithOptions, false},
		{"fail no subject", args{"", []token.Options{}}, nil, true},
		{"fail bad option", args{"test.domain", []token.Options{token.WithIssuer("")}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.subject, tt.args.opts...)
			withFixedTime(got, now)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, got, tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_SignedString(t *testing.T) {
	type fields struct {
		claims *token.Claims
	}
	type args struct {
		sigAlg string
		key    interface{}
	}

	rsaKey, err := pemutil.Read("../../crypto/pemutil/testdata/openssl.rsa1024.pem")
	if err != nil {
		t.Fatal(err)
	}

	rsaPublic := rsaKey.(*rsa.PrivateKey).Public()
	expected := "eyJhbGciOiJSUzI1NiIsImtpZCI6Im50U2lnZFFZNHRLOFlmTDdHQjZjNGRuZzhvSGVGOU5VMkl0QUlVOGtHZGciLCJ0eXAiOiJKV1QifQ.e30.spzx_GFrhXg_LTPBIE3z3uWaA-GH7G0rbPdskxbUahJnXRLwF8S_AAQMTjtsWY9iELwOQQUXW7aPES-jONCebTpXl00RYP7maiS87wcGW6nZ0ICmsbS5NnCDJIKpV4Ei3MZ4MXfZ4vLaONaR5BunHYkicMDqWif_2v8yvxebh7c"

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{"ok", fields{&token.Claims{}}, args{"RS256", rsaKey}, expected, false},
		{"fail bad alg", fields{&token.Claims{}}, args{"ES256", rsaKey}, "", true},
		{"fail with public", fields{&token.Claims{}}, args{"RS256", rsaPublic}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &Token{
				claims: tt.fields.claims,
			}
			got, err := tok.SignedString(tt.args.sigAlg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Token.SignedString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Token.SignedString() = %v, want %v", got, tt.want)
			}
		})
	}
}
