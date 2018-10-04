package token

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/jose"
)

const (
	// DefaultIssuer when generating tokens.
	DefaultIssuer = "step-cli"
	// DefaultAudience when generating tokens.
	DefaultAudience = "https://ca/sign"
	// MinValidity token validity token duration.
	MinValidity = 10 * time.Second
	// MaxValidity token validity token duration.
	MaxValidity = 1 * time.Hour
	// DefaultValidity token validity duration.
	DefaultValidity = 5 * time.Minute
	// MaxValidityDelay allowable delay between Now and beginning of token validity period.
	MaxValidityDelay = 30 * time.Minute
)

const (
	// CAClaim is the property name for a JWT claim that stores the address of a
	// certificate authority.
	CAClaim = "ca"
	// RootSHAClaim is the property name for a JWT claim that stores the SHA256 of a root certificate.
	RootSHAClaim = "sha"
)

// Token interface which all token types should attempt to implement.
type Token interface {
	SignedString(sigAlg string, priv interface{}) (string, error)
}

// Claims represents the claims that a token might have.
type Claims struct {
	jose.Claims
	ExtraClaims map[string]interface{}
}

// Set adds the given key and value to the map of extra claims.
func (c *Claims) Set(key string, value interface{}) {
	if c.ExtraClaims == nil {
		c.ExtraClaims = make(map[string]interface{})
	}
	c.ExtraClaims[key] = value
}

// Sign creates a JWT with the claims and signs it with the given key.
func (c *Claims) Sign(alg jose.SignatureAlgorithm, key interface{}) (string, error) {
	kid, err := GenerateKeyID(key)
	if err != nil {
		return "", err
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", kid)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, so)
	if err != nil {
		return "", errors.Wrapf(err, "error creating JWT signer")
	}

	// Force aud to be a string
	if len(c.Audience) == 1 {
		c.Set("aud", c.Audience[0])
	}

	raw, err := jose.Signed(signer).Claims(c.Claims).Claims(c.ExtraClaims).CompactSerialize()
	if err != nil {
		return "", errors.Wrapf(err, "error serializing JWT")
	}
	return raw, nil
}

// NewClaims returns the default claims with the given options added.
func NewClaims(opts ...Options) (*Claims, error) {
	c := DefaultClaims()
	for _, fn := range opts {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// DefaultClaims returns the default claims of any token.
func DefaultClaims() *Claims {
	now := time.Now()
	return &Claims{
		Claims: jose.Claims{
			Issuer:    DefaultIssuer,
			Audience:  jose.Audience{DefaultAudience},
			Expiry:    jose.NewNumericDate(now.Add(DefaultValidity)),
			NotBefore: jose.NewNumericDate(now),
			IssuedAt:  jose.NewNumericDate(now),
		},
		ExtraClaims: make(map[string]interface{}),
	}
}

// GenerateKeyID returns the SHA256 of a public key.
func GenerateKeyID(priv interface{}) (string, error) {
	pub, err := keys.PublicKey(priv)
	if err != nil {
		return "", errors.Wrap(err, "error generating kid")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", errors.Wrap(err, "error generating kid")
	}

	pubChecksum := sha256.Sum256(pubBytes)
	return hex.EncodeToString(pubChecksum[:]), nil
}
