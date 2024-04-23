package token

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
)

// Type indicates the token Type.
type Type int

// Token types supported.
const (
	Unknown Type = iota
	JWK          // Smallstep JWK
	X5C          // Smallstep JWK with x5c header
	OIDC         // OpenID Connect
	GCP          // Google Cloud Platform
	AWS          // Amazon Web Services
	Azure        // Microsoft Azure
	K8sSA        // Kubernetes Service Account
	Nebula       // Nebula, a JWT with nebula header
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
	SHA                     string            `json:"sha"`     // JWK token claims
	SANs                    []string          `json:"sans"`    // ...
	AtHash                  string            `json:"at_hash"` // OIDC token claims
	AuthorizedParty         string            `json:"azp"`     // ...
	Email                   string            `json:"email"`
	EmailVerified           bool              `json:"email_verified"`
	Hd                      string            `json:"hd"`
	Nonce                   string            `json:"nonce"`
	AppID                   string            `json:"appid"`    // Azure token claims
	AppIDAcr                string            `json:"appidacr"` // ...
	IdentityProvider        string            `json:"idp"`
	ObjectID                string            `json:"oid"`
	TenantID                string            `json:"tid"`
	Version                 interface{}       `json:"ver"`
	XMSMirID                string            `json:"xms_mirid"`
	K8sSANamespace          string            `json:"kubernetes.io/serviceaccount/namespace,omitempty"`
	K8sSASecretName         string            `json:"kubernetes.io/serviceaccount/secret.name,omitempty"`
	K8sSAServiceAccountName string            `json:"kubernetes.io/serviceaccount/service-account.name,omitempty"`
	K8sSAServiceAccountUID  string            `json:"kubernetes.io/serviceaccount/service-account.uid,omitempty"`
	Google                  *GCPGooglePayload `json:"google"` // GCP token claims
	Amazon                  *AWSAmazonPayload `json:"amazon"` // AWS token claims
	Azure                   *AzurePayload     `json:"azure"`  // Azure token claims
}

// Type returns the type of the payload.
func (p Payload) Type() Type {
	switch {
	case p.Google != nil:
		return GCP
	case p.Amazon != nil:
		return AWS
	case p.Azure != nil:
		return Azure
	case p.Issuer == "kubernetes/serviceaccount":
		return K8sSA
	case p.SHA != "" || len(p.SANs) > 0:
		return JWK
	case len(p.Audience) > 0 && p.Issuer != "" && p.Subject != "" && !p.Expiry.Time().IsZero() && !p.IssuedAt.Time().IsZero():
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

// AWSAmazonPayload represents the Amazon payload for a AWS token.
type AWSAmazonPayload struct {
	Document                 []byte                       `json:"document"`
	Signature                []byte                       `json:"signature"`
	InstanceIdentityDocument *AWSInstanceIdentityDocument `json:"-"`
}

// AWSInstanceIdentityDocument is the JSON representation of the instance
// identity document.
type AWSInstanceIdentityDocument struct {
	AccountID          string    `json:"accountId"`
	Architecture       string    `json:"architecture"`
	AvailabilityZone   string    `json:"availabilityZone"`
	BillingProducts    []string  `json:"billingProducts"`
	DevpayProductCodes []string  `json:"devpayProductCodes"`
	ImageID            string    `json:"imageId"`
	InstanceID         string    `json:"instanceId"`
	InstanceType       string    `json:"instanceType"`
	KernelID           string    `json:"kernelId"`
	PendingTime        time.Time `json:"pendingTime"`
	PrivateIP          string    `json:"privateIp"`
	RamdiskID          string    `json:"ramdiskId"`
	Region             string    `json:"region"`
	Version            string    `json:"version"`
}

// azureXMSMirIDRegExp is the regular expression used to parse the xms_mirid claim.
// Using case insensitive as resourceGroups appears as resourcegroups.
var azureXMSMirIDRegExp = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.(Compute/virtualMachines|ManagedIdentity/userAssignedIdentities)/([^/]+)$`)

// AzurePayload contains the information in the xms_mirid claim.
type AzurePayload struct {
	SubscriptionID string
	ResourceGroup  string
	ResourceType   string
	ResourceName   string
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

	return parseResponse(jwt, p)
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

	return parseResponse(jwt, p)
}

func parseResponse(jwt *jose.JSONWebToken, p Payload) (*JSONWebToken, error) {
	switch {
	case p.Type() == AWS:
		if err := json.Unmarshal(p.Amazon.Document, &p.Amazon.InstanceIdentityDocument); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling instance identity document")
		}
	case isAzurePayload(p):
		if re := azureXMSMirIDRegExp.FindStringSubmatch(p.XMSMirID); len(re) > 0 {
			p.Azure = &AzurePayload{
				SubscriptionID: re[1],
				ResourceGroup:  re[2],
				ResourceType:   strings.Split(re[3], "/")[1],
				ResourceName:   re[4],
			}
		}
	}

	return &JSONWebToken{
		JSONWebToken: jwt,
		Payload:      p,
	}, nil
}

func isAzurePayload(p Payload) bool {
	azureTokenIssuerPrefixes := []string{
		"https://sts.windows.net",
		"https://login.microsoftonline.com",
		"https://login.microsoftonline.us",
		"https://sts.chinacloudapi.cn",
		"https://login.partner.microsoftonline.cn",
	}

	for _, prefix := range azureTokenIssuerPrefixes {
		if strings.HasPrefix(p.Issuer, prefix) {
			return true
		}
	}
	return false
}
