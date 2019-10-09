package cautils

import (
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
)

// TokenGenerator is a helper used to generate different types of tokens used in
// the CA.
type TokenGenerator struct {
	kid, iss, aud       string
	root                string
	notBefore, notAfter time.Time
	jwk                 *jose.JSONWebKey
}

// NewTokenGenerator initializes a new token generator with the common fields.
func NewTokenGenerator(kid, iss, aud, root string, notBefore, notAfter time.Time, jwk *jose.JSONWebKey) *TokenGenerator {
	return &TokenGenerator{
		kid:       kid,
		iss:       iss,
		aud:       aud,
		root:      root,
		notBefore: notBefore,
		notAfter:  notAfter,
		jwk:       jwk,
	}
}

// Token generates a generic token with the given subject and options.
func (t *TokenGenerator) Token(sub string, opts ...token.Options) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(t.kid),
		token.WithIssuer(t.iss),
		token.WithAudience(t.aud),
	}
	if len(t.root) > 0 {
		tokOptions = append(tokOptions, token.WithRootCA(t.root))
	}

	// Add custom options
	for _, o := range opts {
		tokOptions = append(tokOptions, o)
	}

	// Add token validity
	notBefore, notAfter := t.notBefore, t.notAfter
	if !notBefore.IsZero() || !notAfter.IsZero() {
		if notBefore.IsZero() {
			notBefore = time.Now()
		}
		if notAfter.IsZero() {
			notAfter = notBefore.Add(token.DefaultValidity)
		}
		tokOptions = append(tokOptions, token.WithValidity(notBefore, notAfter))
	}

	tok, err := provision.New(sub, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(t.jwk.Algorithm, t.jwk.Key)
}

// SignToken generates a X.509 certificate signing token. If sans is empty, we
// will use the subject (common name) as the only SAN.
func (t *TokenGenerator) SignToken(sub string, sans []string) (string, error) {
	if len(sans) == 0 {
		sans = []string{sub}
	}
	return t.Token(sub, token.WithSANS(sans))
}

// RevokeToken generates a X.509 certificate revoke token.
func (t *TokenGenerator) RevokeToken(sub string) (string, error) {
	return t.Token(sub)
}

// SignSSHToken generates a SSH certificate signing token.
func (t *TokenGenerator) SignSSHToken(sub, certType string, principals []string, notBefore, notAfter provisioner.TimeDuration) (string, error) {
	return t.Token(sub, token.WithSSH(provisioner.SSHOptions{
		CertType:    certType,
		Principals:  principals,
		ValidAfter:  notBefore,
		ValidBefore: notAfter,
	}))
}
