package token

import (
	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

// Type indicates the token Type.
type Type int

// Token types supported.
const (
	Unknown Type = iota
	JWK          // Smallstep JWK
	OIDC         // OpenID Connect
	GCP          // Google Cloud Platform
)

// JSONWebToken represents a JSON Web Token (as specified in RFC7519). Using the
// Parse or ParseInsecure it will contain the payloads supported on step ca.
type JSONWebToken struct {
	*jose.JSONWebToken
	Payload Payload
}

// Payload represents public claim values (as specified in RFC 7519). In
// addition to the standard claims it contains the ones supported in step ca.
type Payload struct {
	jose.Claims
	SHA             string            `json:"sha"`     // JWK token claims
	SANs            []string          `json:"sans"`    // ...
	AtHash          string            `json:"at_hash"` // OIDC token claims
	AuthorizedParty string            `json:"azp"`     // ...
	Email           string            `json:"email"`
	EmailVerified   bool              `json:"email_verified"`
	Hd              string            `json:"hd"`
	Nonce           string            `json:"nonce"`
	Google          *GCPGooglePayload `json:"google"` // GCP token claims
}

// Type returns the type of the payload.
func (p Payload) Type() Type {
	switch {
	case len(p.SHA) > 0 || len(p.SANs) > 0:
		return JWK
	case p.Google != nil:
		return GCP
	case p.Email != "":
		return OIDC
	default:
		return Unknown
	}
}

// GCPGooglePayload represents the Google payload in GCP.
type GCPGooglePayload struct {
	ComputeEngine GCPComputeEnginePayload `json:"compute_engine"`
}

// GCPComputeEnginePayload represents the Google ComputeEngine payload in GCP.
type GCPComputeEnginePayload struct {
	InstanceID                string            `json:"instance_id"`
	InstanceName              string            `json:"instance_name"`
	InstanceCreationTimestamp *jose.NumericDate `json:"instance_creation_timestamp"`
	ProjectID                 string            `json:"project_id"`
	ProjectNumber             int64             `json:"project_number"`
	Zone                      string            `json:"zone"`
	LicenseID                 []string          `json:"license_id"`
}

// Parse parses the given token verifying the signature with the key.
func Parse(token string, key interface{}) (*JSONWebToken, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing token")
	}

	var p Payload
	if err := jwt.Claims(key, &p); err != nil {
		return nil, errors.Wrap(err, "error parsing token claims")
	}

	return &JSONWebToken{
		JSONWebToken: jwt,
		Payload:      p,
	}, nil
}

// ParseInsecure parses the given token.
func ParseInsecure(token string) (*JSONWebToken, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing token")
	}

	var p Payload
	if err := jwt.UnsafeClaimsWithoutVerification(&p); err != nil {
		return nil, errors.Wrap(err, "error parsing token claims")
	}

	return &JSONWebToken{
		JSONWebToken: jwt,
		Payload:      p,
	}, nil
}
