package joseutil

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestParseSignedInsecure(t *testing.T) {
	payload := b64(`{"sub":"x"}`)
	sig := b64("signature")
	compact := func(header string) string {
		return b64(header) + "." + payload + "." + sig
	}

	tests := []struct {
		name  string
		token string
		want  []string
	}{
		{"supported alg", compact(`{"alg":"ES256"}`), []string{"ES256"}},
		{"none", compact(`{"alg":"none"}`), []string{"none"}},
		{"none without signature", b64(`{"alg":"none"}`) + "." + payload + ".", []string{"none"}},
		{"not allow-listed alg", compact(`{"alg":"ES256K"}`), []string{"ES256K"}},
		{"unknown alg", compact(`{"alg":"FOO"}`), []string{"FOO"}},
		{"no alg", compact(`{"typ":"JWT"}`), []string{""}},
		{"null alg", compact(`{"alg":null}`), []string{""}},
		{"whitespace", " " + compact(`{"alg":"none"}`) + "\n", []string{"none"}},
		{
			"flattened JSON",
			`{"payload":"` + payload + `","protected":"` + b64(`{"alg":"none"}`) + `","signature":"` + sig + `"}`,
			[]string{"none"},
		},
		{
			"flattened JSON with alg in the unprotected header",
			`{"payload":"` + payload + `","protected":"` + b64(`{"typ":"JWT"}`) + `","header":{"alg":"FOO"},"signature":"` + sig + `"}`,
			[]string{"FOO"},
		},
		{
			"general JSON with multiple signatures",
			`{"payload":"` + payload + `","signatures":[` +
				`{"protected":"` + b64(`{"alg":"none"}`) + `","signature":"` + sig + `"},` +
				`{"protected":"` + b64(`{"alg":"ES256K"}`) + `","signature":"` + sig + `"},` +
				`{"protected":"` + b64(`{"typ":"JWT"}`) + `","header":{"alg":"FOO"},"signature":"` + sig + `"}]}`,
			[]string{"none", "ES256K", "FOO"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := ParseSignedInsecure(tc.token)
			require.NoError(t, err)

			got := make([]string, len(tok.Signatures))
			for i := range tok.Signatures {
				got[i] = tok.Signatures[i].Header.Algorithm
			}
			assert.Equal(t, tc.want, got)
			assert.JSONEq(t, `{"sub":"x"}`, string(tok.UnsafePayloadWithoutVerification()))
		})
	}
}

func TestParseSignedInsecure_errors(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"not a token", "foo", "compact JWS format must have three parts"},
		{"invalid header encoding", "!!!." + b64("{}") + ".", "illegal base64 data"},
		{"invalid header JSON", b64("foo") + "." + b64("{}") + ".", "invalid protected header"},
		{"alg is not a string", b64(`{"alg":42}`) + "." + b64("{}") + ".", "failed to unmarshal algorithm"},
		{"invalid JSON", `{"payload":`, "unexpected end of JSON input"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSignedInsecure(tc.token)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestParseSignedInsecure_jsonWithoutSignature(t *testing.T) {
	tok, err := ParseSignedInsecure(`{"payload":"` + b64(`{"sub":"x"}`) + `"}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"sub":"x"}`, string(tok.UnsafePayloadWithoutVerification()))
}

// The result of ParseSignedInsecure must not make it possible to accept a token
// without a valid signature.
func TestParseSignedInsecure_doesNotVerify(t *testing.T) {
	tok, err := ParseSignedInsecure(b64(`{"alg":"none"}`) + "." + b64(`{"sub":"x"}`) + ".")
	require.NoError(t, err)

	_, err = tok.Verify([]byte("a-key-that-does-not-sign-this-token"))
	assert.Error(t, err)
}

func TestParseEncryptedInsecure(t *testing.T) {
	part := b64("aaaaaaaa")
	rest := "." + part + "." + part + "." + part + "." + part
	jsonRest := `"iv":"` + part + `","ciphertext":"` + part + `","tag":"` + part + `"`

	tests := []struct {
		name    string
		token   string
		wantAlg string
		wantEnc string
	}{
		{"supported", b64(`{"alg":"A256KW","enc":"A256GCM"}`) + rest, "A256KW", "A256GCM"},
		{"unknown alg", b64(`{"alg":"FOO","enc":"A256GCM"}`) + rest, "FOO", "A256GCM"},
		{"unknown enc", b64(`{"alg":"A256KW","enc":"BAR"}`) + rest, "A256KW", "BAR"},
		{"whitespace", " " + b64(`{"alg":"FOO","enc":"BAR"}`) + rest + "\n", "FOO", "BAR"},
		{
			"flattened JSON",
			`{"protected":"` + b64(`{"alg":"FOO","enc":"BAR"}`) + `","encrypted_key":"` + part + `",` + jsonRest + `}`,
			"FOO", "BAR",
		},
		{
			"flattened JSON with shared unprotected header",
			`{"protected":"` + b64(`{"typ":"JWT"}`) + `","unprotected":{"alg":"FOO","enc":"BAR"},"encrypted_key":"` + part + `",` + jsonRest + `}`,
			"FOO", "BAR",
		},
		{
			"flattened JSON with per-recipient header",
			`{"protected":"` + b64(`{"enc":"BAR"}`) + `","header":{"alg":"FOO"},"encrypted_key":"` + part + `",` + jsonRest + `}`,
			"", "BAR",
		},
		{
			"general JSON with multiple recipients",
			`{"protected":"` + b64(`{"enc":"BAR"}`) + `","recipients":[` +
				`{"header":{"alg":"FOO"},"encrypted_key":"` + part + `"},` +
				`{"header":{"alg":"BAZ"},"encrypted_key":"` + part + `"}],` + jsonRest + `}`,
			"", "BAR",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := ParseEncryptedInsecure(tc.token)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAlg, tok.Header.Algorithm)
			assert.Equal(t, tc.wantEnc, tok.Header.ExtraHeaders["enc"])
		})
	}
}

func TestParseEncryptedInsecure_errors(t *testing.T) {
	_, err := ParseEncryptedInsecure("foo")
	assert.Error(t, err)

	part := b64("aaaaaaaa")
	rest := "." + part + "." + part + "." + part + "." + part
	_, err = ParseEncryptedInsecure(b64(`{"enc":"A256GCM"}`) + rest)
	assert.ErrorContains(t, err, `missing header "alg"`)

	_, err = ParseEncryptedInsecure(b64(`{"alg":"A256KW"}`) + rest)
	assert.ErrorContains(t, err, `missing header "enc"`)

	_, err = ParseEncryptedInsecure(b64(`{"alg":"none"}`) + "." + b64("{}") + ".")
	assert.Error(t, err)

	_, err = ParseEncryptedInsecure(`{"protected":`)
	assert.Error(t, err)
}
