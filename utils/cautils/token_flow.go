package cautils

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

type provisionersSelect struct {
	Name        string
	Provisioner provisioner.Interface
}

// Token signing types
const (
	SignType = iota
	RevokeType
	SSHUserSignType
	SSHHostSignType
)

// parseAudience creates the ca audience url from the ca-url
func parseAudience(ctx *cli.Context, tokType int) (string, error) {
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return "", errs.RequiredFlag(ctx, "ca-url")
	}

	audience, err := url.Parse(caURL)
	if err != nil {
		return "", errs.InvalidFlagValue(ctx, "ca-url", caURL, "")
	}
	switch strings.ToLower(audience.Scheme) {
	case "https", "":
		var path string
		switch tokType {
		// default
		case SignType, SSHUserSignType, SSHHostSignType:
			path = "/1.0/sign"
		// revocation token
		case RevokeType:
			path = "/1.0/revoke"
		default:
			return "", errors.Errorf("unexpected token type: %d", tokType)
		}
		audience.Scheme = "https"
		audience = audience.ResolveReference(&url.URL{Path: path})
		return audience.String(), nil
	default:
		return "", errs.InvalidFlagValue(ctx, "ca-url", caURL, "")
	}
}

// ErrACMEToken is the error type returned when the user attempts a Token Flow
// while using an ACME provisioner.
type ErrACMEToken struct {
	Name string
}

// Error implements the error interface.
func (e *ErrACMEToken) Error() string {
	return "step ACME provisioners do not support token auth flows"
}

// NewTokenFlow implements the common flow used to generate a token
func NewTokenFlow(ctx *cli.Context, typ int, subject string, sans []string, caURL, root string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration) (string, error) {
	// Get audience from ca-url
	audience, err := parseAudience(ctx, typ)
	if err != nil {
		return "", err
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return "", err
	}

	p, err := provisionerPrompt(ctx, provisioners)
	if err != nil {
		return "", err
	}

	switch p := p.(type) {
	case *provisioner.OIDC: // Run step oauth
		args := []string{"oauth", "--oidc", "--bare",
			"--provider", p.ConfigurationEndpoint,
			"--client-id", p.ClientID, "--client-secret", p.ClientSecret}
		if ctx.IsSet("console") {
			args = append(args, "--console")
		}
		out, err := exec.Step(args...)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	case *provisioner.GCP: // Do the identity request to get the token
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, caURL)
	case *provisioner.AWS: // Do the identity request to get the token
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, caURL)
	case *provisioner.Azure: // Do the identity request to get the token
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, caURL)
	case *provisioner.ACME: // Return an error with the provisioner ID
		return "", &ErrACMEToken{p.GetName()}
	}

	// JWK provisioner
	prov, ok := p.(*provisioner.JWK)
	if !ok {
		return "", errors.Errorf("unknown provisioner type %T", p)
	}

	kid := prov.Key.KeyID
	issuer := prov.Name

	var opts []jose.Option
	if passwordFile := ctx.String("password-file"); len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}

	var jwk *jose.JSONWebKey
	if keyFile := ctx.String("key"); len(keyFile) == 0 {
		// Get private key from CA
		encrypted, err := pki.GetProvisionerKey(caURL, root, kid)
		if err != nil {
			return "", err
		}

		// Add template with check mark
		opts = append(opts, jose.WithUIOptions(
			ui.WithPromptTemplates(ui.PromptTemplates()),
		))

		decrypted, err := jose.Decrypt("Please enter the password to decrypt the provisioner key", []byte(encrypted), opts...)
		if err != nil {
			return "", err
		}

		jwk = new(jose.JSONWebKey)
		if err := json.Unmarshal(decrypted, jwk); err != nil {
			return "", errors.Wrap(err, "error unmarshalling provisioning key")
		}
	} else {
		// Get private key from given key file
		jwk, err = jose.ParseKey(keyFile, opts...)
		if err != nil {
			return "", err
		}
	}

	// Generate token
	tokenGen := NewTokenGenerator(kid, issuer, audience, root, notBefore, notAfter, jwk)
	switch typ {
	case SignType:
		return tokenGen.SignToken(subject, sans)
	case RevokeType:
		return tokenGen.RevokeToken(subject)
	case SSHUserSignType:
		return tokenGen.SignSSHToken(subject, provisioner.SSHUserCert, sans, certNotBefore, certNotAfter)
	case SSHHostSignType:
		return tokenGen.SignSSHToken(subject, provisioner.SSHHostCert, sans, certNotBefore, certNotAfter)
	default:
		return tokenGen.Token(subject)
	}
}

// OfflineTokenFlow generates a provisioning token using either
//   1. static configuration from ca.json (created with `step ca init`)
//   2. input from command line flags
// These two options are mutually exclusive and priority is given to ca.json.
func OfflineTokenFlow(ctx *cli.Context, typ int, subject string, sans []string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration) (string, error) {
	caConfig := ctx.String("ca-config")
	if caConfig == "" {
		return "", errs.InvalidFlagValue(ctx, "ca-config", "", "")
	}

	// Using the offline CA
	if utils.FileExists(caConfig) {
		offlineCA, err := NewOfflineCA(caConfig)
		if err != nil {
			return "", err
		}
		return offlineCA.GenerateToken(ctx, typ, subject, sans, notBefore, notAfter, certNotBefore, certNotAfter)
	}

	kid := ctx.String("kid")
	issuer := ctx.String("issuer")
	keyFile := ctx.String("key")
	passwordFile := ctx.String("password-file")

	// Require issuer and keyFile if ca.json does not exists.
	// kid can be passed or created using jwk.Thumbprint.
	switch {
	case len(issuer) == 0:
		return "", errs.RequiredWithFlag(ctx, "offline", "issuer")
	case len(keyFile) == 0:
		return "", errs.RequiredWithFlag(ctx, "offline", "key")
	}

	// Get audience from ca-url
	audience, err := parseAudience(ctx, typ)
	if err != nil {
		return "", err
	}

	// Get root from argument or default location
	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if utils.FileExists(root) {
			return "", errs.RequiredFlag(ctx, "root")
		}
	}

	// Parse key
	var opts []jose.Option
	if len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}
	jwk, err := jose.ParseKey(keyFile, opts...)
	if err != nil {
		return "", err
	}

	// Get the kid if it's not passed as an argument
	if len(kid) == 0 {
		hash, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return "", errors.Wrap(err, "error generating JWK thumbprint")
		}
		kid = base64.RawURLEncoding.EncodeToString(hash)
	}

	// Generate token
	tokenGen := NewTokenGenerator(kid, issuer, audience, root, notBefore, notAfter, jwk)
	switch typ {
	case SignType:
		return tokenGen.SignToken(subject, sans)
	case RevokeType:
		return tokenGen.RevokeToken(subject)
	case SSHUserSignType:
		return tokenGen.SignSSHToken(subject, provisioner.SSHUserCert, sans, certNotBefore, certNotAfter)
	case SSHHostSignType:
		return tokenGen.SignSSHToken(subject, provisioner.SSHHostCert, sans, certNotBefore, certNotAfter)
	default:
		return tokenGen.Token(subject)
	}
}

func provisionerPrompt(ctx *cli.Context, provisioners provisioner.List) (provisioner.Interface, error) {
	// Filter by type
	provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
		switch p.GetType() {
		case provisioner.TypeJWK, provisioner.TypeOIDC, provisioner.TypeACME:
			return true
		case provisioner.TypeGCP, provisioner.TypeAWS, provisioner.TypeAzure:
			return true
		default:
			return false
		}
	})

	if len(provisioners) == 0 {
		return nil, errors.New("cannot create a new token: the CA does not have any provisioner configured")
	}

	// Filter by kid
	if kid := ctx.String("kid"); len(kid) != 0 {
		provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
			switch p := p.(type) {
			case *provisioner.JWK:
				return p.Key.KeyID == kid
			case *provisioner.OIDC:
				return p.ClientID == kid
			default:
				return false
			}
		})
		if len(provisioners) == 0 {
			return nil, errs.InvalidFlagValue(ctx, "kid", kid, "")
		}
	}

	// Filter by issuer (provisioner name)
	if issuer := ctx.String("issuer"); len(issuer) != 0 {
		provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
			return p.GetName() == issuer
		})
		if len(provisioners) == 0 {
			return nil, errs.InvalidFlagValue(ctx, "issuer", issuer, "")
		}
	}

	// Select provisioner
	var items []*provisionersSelect
	for _, prov := range provisioners {
		switch p := prov.(type) {
		case *provisioner.JWK:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s) [kid: %s]", p.Name, p.GetType(), p.Key.KeyID),
				Provisioner: p,
			})
		case *provisioner.OIDC:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s) [client: %s]", p.Name, p.GetType(), p.ClientID),
				Provisioner: p,
			})
		case *provisioner.GCP:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s)", p.Name, p.GetType()),
				Provisioner: p,
			})
		case *provisioner.AWS:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s)", p.Name, p.GetType()),
				Provisioner: p,
			})
		case *provisioner.Azure:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s) [tenant: %s]", p.Name, p.GetType(), p.TenantID),
				Provisioner: p,
			})
		case *provisioner.ACME:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s)", p.Name, p.GetType()),
				Provisioner: p,
			})
		default:
			continue
		}
	}

	if len(items) == 1 {
		if err := ui.PrintSelected("Provisioner", items[0].Name); err != nil {
			return nil, err
		}
		return items[0].Provisioner, nil
	}

	i, _, err := ui.Select("What provisioner key do you want to use?", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Provisioner")))
	if err != nil {
		return nil, err
	}

	return items[i].Provisioner, nil
}

// provisionerFilter returns a slice of provisioners that pass the given filter.
func provisionerFilter(provisioners provisioner.List, f func(provisioner.Interface) bool) provisioner.List {
	var result provisioner.List
	for _, p := range provisioners {
		if f(p) {
			result = append(result, p)
		}
	}
	return result
}
