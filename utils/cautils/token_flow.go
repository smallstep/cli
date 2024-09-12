package cautils

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
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
	SSHRevokeType
	SSHRenewType
	SSHRekeyType
	RenewType
)

// parseAudience creates the ca audience url from the ca-url
func parseAudience(ctx *cli.Context, tokType int) (string, error) {
	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return "", err
	}

	audience, err := url.Parse(caURL)
	if err != nil {
		return "", errs.InvalidFlagValue(ctx, "ca-url", caURL, "")
	}
	switch strings.ToLower(audience.Scheme) {
	case "https", "":
		var path string
		switch tokType {
		case SignType:
			path = "/1.0/sign"
		case RenewType:
			path = "/1.0/renew"
		case RevokeType:
			path = "/1.0/revoke"
		case SSHUserSignType, SSHHostSignType:
			path = "/1.0/ssh/sign"
		case SSHRevokeType:
			path = "/1.0/ssh/revoke"
		case SSHRenewType:
			path = "/1.0/ssh/renew"
		case SSHRekeyType:
			path = "/1.0/ssh/rekey"
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

// ACMETokenError is the error type returned when the user attempts a Token Flow
// while using an ACME provisioner.
type ACMETokenError struct {
	Name string
}

// Error implements the error interface.
func (e *ACMETokenError) Error() string {
	return "step ACME provisioners do not support token auth flows"
}

// NewTokenFlow implements the common flow used to generate a token
func NewTokenFlow(ctx *cli.Context, tokType int, subject string, sans []string, caURL, root string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration, opts ...Option) (string, error) {
	// Apply options to shared context
	for _, opt := range opts {
		opt.apply(&sharedContext)
	}

	// Get audience from ca-url
	audience, err := parseAudience(ctx, tokType)
	if err != nil {
		return "", err
	}

	// All provisioners use the same type of tokens to do a X.509 renewal.
	if tokType == RenewType {
		return generateRenewToken(ctx, audience, subject)
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return "", err
	}
	p, err := provisionerPrompt(ctx, provisioners)
	if err != nil {
		return "", err
	}

	if subject == "" {
		// For OIDC provisioners the CA automatically generates the principals
		// from the email address.
		if _, ok := p.(*provisioner.OIDC); !ok {
			q := "What DNS names or IP addresses would you like to use? (e.g. internal.smallstep.com)"
			if tokType == SSHUserSignType {
				q = "What user principal would you like to use? (e.g. alice)"
			}
			subject, err = ui.Prompt(q, ui.WithValidateNotEmpty())
			if err != nil {
				return "", err
			}
		}
	}

	tokAttrs := tokenAttrs{
		subject:       subject,
		root:          root,
		caURL:         caURL,
		audience:      audience,
		sans:          sans,
		notBefore:     notBefore,
		notAfter:      notAfter,
		certNotBefore: certNotBefore,
		certNotAfter:  certNotAfter,
	}

	switch p := p.(type) {
	case *provisioner.JWK: // Get the step standard JWT.
		return generateJWKToken(ctx, p, tokType, tokAttrs)
	case *provisioner.OIDC: // Run step oauth.
		return generateOIDCToken(ctx, p)
	case *provisioner.X5C: // Get a JWT with an X5C header and signature.
		return generateX5CToken(ctx, p, tokType, tokAttrs)
	case *provisioner.Nebula:
		return generateNebulaToken(ctx, p, tokType, tokAttrs)
	case *provisioner.SSHPOP: // Generate a SSHPOP token using an ssh cert + key.
		return generateSSHPOPToken(ctx, p, tokType, tokAttrs)
	case *provisioner.K8sSA: // Get the Kubernetes service account token.
		return generateK8sSAToken(ctx)
	case *provisioner.GCP: // Do the identity request to get the token.
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, caURL)
	case *provisioner.AWS: // Do the identity request to get the token.
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, caURL)
	case *provisioner.Azure: // Do the identity request to get the token.
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, caURL)
	case *provisioner.ACME: // Return an error with the provisioner ID.
		return "", &ACMETokenError{p.GetName()}
	default:
		return "", errors.Errorf("unknown provisioner type %T", p)
	}
}

// NewIdentityTokenFlow implements the flow to generate a token using only an
// OIDC provisioner.
func NewIdentityTokenFlow(ctx *cli.Context, caURL, root string) (string, error) {
	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return "", err
	}
	provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
		return p.GetType() == provisioner.TypeOIDC
	})
	p, err := provisionerPrompt(ctx, provisioners)
	if err != nil {
		return "", err
	}
	switch p := p.(type) {
	case *provisioner.OIDC:
		return generateOIDCToken(ctx, p)
	default:
		return "", errors.Errorf("bootstrap flow does not support the %s provisioner", p.GetType())
	}
}

// OfflineTokenFlow generates a provisioning token using either
//  1. static configuration from ca.json (created with `step ca init`)
//  2. input from command line flags
//
// These two options are mutually exclusive and priority is given to ca.json.
func OfflineTokenFlow(ctx *cli.Context, typ int, subject string, sans []string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration) (string, error) {
	caConfig := ctx.String("ca-config")
	if caConfig == "" {
		return "", errs.InvalidFlagValue(ctx, "ca-config", "", "")
	}

	// Using the offline CA
	if utils.FileExists(caConfig) {
		offlineCA, err := NewOfflineCA(ctx, caConfig)
		if err != nil {
			return "", err
		}
		return offlineCA.GenerateToken(ctx, typ, subject, sans, notBefore, notAfter, certNotBefore, certNotAfter)
	}

	kid := ctx.String("kid")
	issuer := ctx.String("issuer")

	// Require issuer and keyFile if ca.json does not exists.
	// kid can be passed or created using jwk.Thumbprint.
	switch {
	case issuer == "":
		return "", errs.RequiredWithFlag(ctx, "offline", "issuer")
	case ctx.String("key") == "":
		return "", errs.RequiredWithFlag(ctx, "offline", "key")
	}

	// Get audience from ca-url
	audience, err := parseAudience(ctx, typ)
	if err != nil {
		return "", err
	}

	// Get root from argument or default location
	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if utils.FileExists(root) {
			return "", errs.RequiredFlag(ctx, "root")
		}
	}

	tokAttrs := tokenAttrs{
		subject:       subject,
		root:          root,
		audience:      audience,
		issuer:        issuer,
		kid:           kid,
		sans:          sans,
		notBefore:     notBefore,
		notAfter:      notAfter,
		certNotBefore: certNotBefore,
		certNotAfter:  certNotAfter,
	}

	switch {
	case ctx.IsSet("x5c-cert") || ctx.IsSet("x5c-key"):
		return generateX5CToken(ctx, nil, typ, tokAttrs)
	default:
		return generateJWKToken(ctx, nil, typ, tokAttrs)
	}
}

func allowX5CProvisionerFilter(p provisioner.Interface) bool {
	return p.GetType() == provisioner.TypeX5C
}

func allowSSHPOPProvisionerFilter(p provisioner.Interface) bool {
	return p.GetType() == provisioner.TypeSSHPOP
}

func allowK8sSAProvisionerFilter(p provisioner.Interface) bool {
	return p.GetType() == provisioner.TypeK8sSA
}

func allowNebulaProvisionerFilter(p provisioner.Interface) bool {
	return p.GetType() == provisioner.TypeNebula
}

func provisionerPrompt(ctx *cli.Context, provisioners provisioner.List) (provisioner.Interface, error) {
	switch {
	// If x5c flags then only list x5c provisioners.
	case ctx.IsSet("x5c-cert") || ctx.IsSet("x5c-key"):
		provisioners = provisionerFilter(provisioners, allowX5CProvisionerFilter)
	// If sshpop flags then only list sshpop provisioners.
	case ctx.IsSet("sshpop-cert") || ctx.IsSet("sshpop-key"):
		provisioners = provisionerFilter(provisioners, allowSSHPOPProvisionerFilter)
	// If k8ssa-token-path flag is set then we must be using the k8sSA provisioner.
	case ctx.IsSet("nebula-cert") || ctx.IsSet("nebula-key"):
		provisioners = provisionerFilter(provisioners, allowNebulaProvisionerFilter)
	case ctx.IsSet("k8ssa-token-path"):
		provisioners = provisionerFilter(provisioners, allowK8sSAProvisionerFilter)
	// List all available provisioners.
	default:
		provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
			switch p.GetType() {
			case provisioner.TypeJWK, provisioner.TypeOIDC,
				provisioner.TypeACME, provisioner.TypeK8sSA,
				provisioner.TypeX5C, provisioner.TypeSSHPOP, provisioner.TypeNebula:
				return true
			case provisioner.TypeGCP, provisioner.TypeAWS, provisioner.TypeAzure:
				return true
			default:
				return false
			}
		})
	}

	if len(provisioners) == 0 {
		return nil, errors.New("cannot create a new token: the CA does not have any provisioner configured")
	}

	// Filter by kid
	if kid := ctx.String("kid"); kid != "" {
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
	if issuer := ctx.String("issuer"); issuer != "" {
		provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
			return p.GetName() == issuer
		})
		if len(provisioners) == 0 {
			return nil, errs.InvalidFlagValue(ctx, "issuer", issuer, "")
		}
	}

	// Filter by admin-provisioner (provisioner name)
	if issuer := ctx.String("admin-provisioner"); issuer != "" {
		provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
			return p.GetName() == issuer
		})
		if len(provisioners) == 0 {
			return nil, errs.InvalidFlagValue(ctx, "admin-provisioner", issuer, "")
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
		case *provisioner.Azure:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s) [tenant: %s]", p.Name, p.GetType(), p.TenantID),
				Provisioner: p,
			})
		case *provisioner.GCP, *provisioner.AWS, *provisioner.X5C, *provisioner.SSHPOP, *provisioner.ACME, *provisioner.Nebula:
			items = append(items, &provisionersSelect{
				Name:        fmt.Sprintf("%s (%s)", p.GetName(), p.GetType()),
				Provisioner: p,
			})
		case *provisioner.K8sSA:
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
