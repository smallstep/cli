// Package joseutil contains helpers for parsing JOSE objects.
package joseutil

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode"

	jose "github.com/go-jose/go-jose/v4"
)

// ParseSignedInsecure parses a JWS in compact or JSON serialization format
// accepting any signature algorithm, including none, unknown, or missing ones. It
// does not verify the signature.
//
// It is meant for commands that only display a token, which must be able to show
// tokens that go.step.sm/crypto/jose.ParseJWS rejects. Only the algorithm check
// is relaxed, go-jose still rejects other invalid headers, like an embedded key
// that it does not support. Do not use it to parse a token that will be verified.
func ParseSignedInsecure(s string) (*jose.JSONWebSignature, error) {
	s = stripWhitespace(s)
	if strings.HasPrefix(s, "{") {
		return jose.ParseSignedJSON(s, signedJSONAlgorithms(s))
	}
	protected, _, _ := strings.Cut(s, ".")
	return jose.ParseSignedCompact(s, []jose.SignatureAlgorithm{
		"", jose.SignatureAlgorithm(protectedField(protected, "alg")),
	})
}

// ParseEncryptedInsecure parses a JWE in compact or JSON serialization format
// accepting any key and content encryption algorithm, including unknown ones.
// They must still be present. It does not decrypt the content.
//
// It is meant for commands that only display a token, which must be able to show
// tokens that go.step.sm/crypto/jose.ParseEncrypted rejects. Only the algorithm
// checks are relaxed, see ParseSignedInsecure. Do not use it to parse a token that
// will be decrypted.
func ParseEncryptedInsecure(s string) (*jose.JSONWebEncryption, error) {
	s = stripWhitespace(s)
	headers := encryptedHeaders(s)

	// go-jose requires non-empty lists, and it reports missing headers itself.
	keyAlgorithms := []jose.KeyAlgorithm{""}
	contentEncryption := []jose.ContentEncryption{""}
	for _, header := range headers {
		keyAlgorithms = append(keyAlgorithms, jose.KeyAlgorithm(headerField(header, "alg")))
		contentEncryption = append(contentEncryption, jose.ContentEncryption(headerField(header, "enc")))
	}
	if strings.HasPrefix(s, "{") {
		return jose.ParseEncryptedJSON(s, keyAlgorithms, contentEncryption)
	}
	return jose.ParseEncryptedCompact(s, keyAlgorithms, contentEncryption)
}

// signedJSONAlgorithms returns the algorithms that the given JWS in JSON
// serialization format declares. Parsing problems are ignored, as go-jose will
// report them. The result always includes the empty algorithm, which is the one
// go-jose reads when a header does not have an alg.
func signedJSONAlgorithms(s string) []jose.SignatureAlgorithm {
	type signature struct {
		Protected string          `json:"protected"`
		Header    json.RawMessage `json:"header"`
	}
	var jws struct {
		signature
		Signatures []signature `json:"signatures"`
	}
	algs := []jose.SignatureAlgorithm{""}
	if err := json.Unmarshal([]byte(s), &jws); err != nil {
		return algs
	}
	for _, sig := range append(jws.Signatures, jws.signature) {
		algs = append(algs,
			jose.SignatureAlgorithm(protectedField(sig.Protected, "alg")),
			jose.SignatureAlgorithm(headerField(sig.Header, "alg")),
		)
	}
	return algs
}

// encryptedHeaders returns the JSON headers of the given JWE. Parsing problems
// are ignored, as go-jose will report them.
func encryptedHeaders(s string) [][]byte {
	if !strings.HasPrefix(s, "{") {
		protected, _, _ := strings.Cut(s, ".")
		return [][]byte{decodeProtected(protected)}
	}

	var jwe struct {
		Protected   string          `json:"protected"`
		Unprotected json.RawMessage `json:"unprotected"`
		Header      json.RawMessage `json:"header"`
		Recipients  []struct {
			Header json.RawMessage `json:"header"`
		} `json:"recipients"`
	}
	if err := json.Unmarshal([]byte(s), &jwe); err != nil {
		return nil
	}
	headers := [][]byte{decodeProtected(jwe.Protected), jwe.Unprotected, jwe.Header}
	for _, recipient := range jwe.Recipients {
		headers = append(headers, recipient.Header)
	}
	return headers
}

// decodeProtected returns the JSON of a base64url encoded protected header, or
// nil if it cannot be decoded.
func decodeProtected(protected string) []byte {
	header, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(protected, "="))
	if err != nil {
		return nil
	}
	return header
}

// protectedField returns a string field of a base64url encoded protected header,
// or an empty string if it does not have one.
func protectedField(protected, name string) string {
	return headerField(decodeProtected(protected), name)
}

// headerField returns a string field of a JSON header, or an empty string if it
// does not have one.
func headerField(header []byte, name string) string {
	var fields map[string]any
	if err := json.Unmarshal(header, &fields); err != nil {
		return ""
	}
	value, _ := fields[name].(string)
	return value
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
