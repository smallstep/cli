package ca

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

type provisionersSelect struct {
	Name        string
	Provisioner provisioner.Interface
}

const (
	signType = iota
	revokeType
)

func tokenCommand() cli.Command {
	return cli.Command{
		Name:   "token",
		Action: command.ActionFunc(tokenAction),
		Usage:  "generate an OTT granting access to the CA",
		UsageText: `**step ca token** <subject>
		[--**kid**=<kid>] [--**issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
		[**--password-file**=<file>] [**--output-file**=<file>] [**--key**=<path>]
		[**--san**=<SAN>] [**--offline**] [**--revoke**]`,
		Description: `**step ca token** command generates a one-time token granting access to the
certificates authority.

## POSITIONAL ARGUMENTS

<subject>
:  The Common Name, DNS Name, or IP address that will be set by the certificate authority.
When there are no additional Subject Alternative Names configured (via the
--san flag), the subject will be added as the only element of the 'sans' claim
on the token.

## EXAMPLES

 Most of the following examples assumes that **--ca-url** and **--root** are
 set using environment variables or the default configuration file in
 <$STEPPATH/config/defaults.json>.

Get a new token for a DNS. Because there are no Subject Alternative Names
configured (via the '--san' flag), the 'sans' claim of the token will have a
default value of ['internal.example.com']:
'''
$ step ca token internal.example.com
'''

Get a new token for a 'Revoke' request:
'''
$ step ca token --revoke 146103349666685108195655980390445292315
'''

Get a new token for an IP address. Because there are no Subject Alternative Names
configured (via the '--san' flag), the 'sans' claim of the token will have a
default value of ['192.168.10.10']:
'''
$ step ca token 192.168.10.10
'''

Get a new token with custom Subject Alternative Names. The value of the 'sans'
claim of the token will be ['1.1.1.1', 'hello.example.com'] - 'foobar' will not
be in the 'sans' claim unless explicitly configured via the '--sans' flag:
'''
$ step ca token foobar --san 1.1.1.1 --san hello.example.com
'''

Get a new token that expires in 30 minutes:
'''
$ step ca token --not-after 30m internal.example.com
'''

Get a new token that becomes valid in 30 minutes and expires 5 minutes after that:
'''
$ step ca token --not-before 30m --not-after 35m internal.example.com
'''

Get a new token signed with the given private key, the public key must be
configured in the certificate authority:
'''
$ step ca token internal.smallstep.com --key token.key
'''

Get a new token for a specific provisioner kid, ca-url and root:
'''
$ step ca token internal.example.com \
    --kid 4vn46fbZT68Uxfs9LBwHkTvrjEvxQqx-W8nnE-qDjts \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt
'''

Get a new token using the simple offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca token internal.example.com --offline
'''

Get a new token using the offline mode with all the parameters:
'''
$ step ca token internal.example.com \
    --offline \
    --kid 4vn46fbZT68Uxfs9LBwHkTvrjEvxQqx-W8nnE-qDjts \
    --issuer you@example.com \
    --key provisioner.key \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt
'''

Get a new token for a 'Revoke' request:
'''
$ step ca token --revoke 146103349666685108195655980390445292315
'''

Get a new token in offline mode for a 'Revoke' request:
'''
$ step ca token --offline --revoke 146103349666685108195655980390445292315
'''
`,
		Flags: []cli.Flag{
			provisionerKidFlag,
			provisionerIssuerFlag,
			caURLFlag,
			rootFlag,
			notBeforeFlag,
			notAfterFlag,
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add DNS or IP Address Subjective Alternative Names (SANs) that the token is
authorized to request. A certificate signing request using this token must match
the complete set of subjective alternative names in the token 1:1. Use the '--san'
flag multiple times to configure multiple SANs.`,
			},
			cli.StringFlag{
				Name: "key",
				Usage: `The private key <path> used to sign the JWT. This is usually downloaded from
the certificate authority.`,
			},
			passwordFileFlag,
			cli.StringFlag{
				Name:  "output-file",
				Usage: "The destination <file> of the generated one-time token.",
			},
			cli.BoolFlag{
				Name: "offline",
				Usage: `Creates a token without contacting the certificate authority. Offline mode
requires the flags <--ca-config> or <--kid>, <--issuer>, <--key>, <--ca-url>, and <--root>.`,
			},
			cli.BoolFlag{
				Name: "revoke",
				Usage: `Create a token for authorizing 'Revoke' requests. The audience will
be invalid for any other API request.`,
			},
			caConfigFlag,
			flags.Force,
		},
	}
}

func tokenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	subject := ctx.Args().Get(0)
	outputFile := ctx.String("output-file")
	offline := ctx.Bool("offline")
	sans := ctx.StringSlice("san")

	// Default token type is always a 'Sign' token.
	typ := signType
	if ctx.Bool("revoke") {
		typ = revokeType
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	// --san and --type revoke are incompatible. Revocation tokens do not support SANs.
	if typ == revokeType && len(sans) > 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "san", "revoke")
	}

	// parse times or durations
	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	var err error
	var token string
	if offline {
		token, err = offlineTokenFlow(ctx, typ, subject, sans)
		if err != nil {
			return err
		}
	} else {
		token, err = newTokenFlow(ctx, typ, subject, sans, caURL, root, notBefore, notAfter)
		if err != nil {
			return err
		}
	}
	if len(outputFile) > 0 {
		return utils.WriteFile(outputFile, []byte(token), 0600)
	}
	fmt.Println(token)
	return nil
}

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
		case signType:
			path = "/1.0/sign"
		// revocation token
		case revokeType:
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

// generateToken generates a provisioning or bootstrap token with the given
// parameters.
func generateToken(typ int, sub string, sans []string, kid, iss, aud, root string, notBefore, notAfter time.Time, jwk *jose.JSONWebKey) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(kid),
		token.WithIssuer(iss),
		token.WithAudience(aud),
	}
	if len(root) > 0 {
		tokOptions = append(tokOptions, token.WithRootCA(root))
	}

	// If 'sign' token then add SANs.
	if typ == signType {
		// If there are no SANs then add the 'subject' (common-name) as the only SAN.
		if len(sans) == 0 {
			sans = []string{sub}
		}
		tokOptions = append(tokOptions, token.WithSANS(sans))
	}

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

	return tok.SignedString(jwk.Algorithm, jwk.Key)
}

// newTokenFlow implements the common flow used to generate a token
func newTokenFlow(ctx *cli.Context, typ int, subject string, sans []string, caURL, root string, notBefore, notAfter time.Time) (string, error) {
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
		out, err := exec.Step("oauth", "--oidc", "--bare",
			"--provider", p.ConfigurationEndpoint,
			"--client-id", p.ClientID, "--client-secret", p.ClientSecret)
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

	return generateToken(typ, subject, sans, kid, issuer, audience, root, notBefore, notAfter, jwk)
}

// offlineTokenFlow generates a provisioning token using either
//   1. static configuration from ca.json (created with `step ca init`)
//   2. input from command line flags
// These two options are mutually exclusive and priority is given to ca.json.
func offlineTokenFlow(ctx *cli.Context, typ int, subject string, sans []string) (string, error) {
	caConfig := ctx.String("ca-config")
	if caConfig == "" {
		return "", errs.InvalidFlagValue(ctx, "ca-config", "", "")
	}

	notBefore, notAfter, err := parseValidity(ctx)
	if err != nil {
		return "", err
	}

	// Using the offline CA
	if utils.FileExists(caConfig) {
		offlineCA, err := newOfflineCA(caConfig)
		if err != nil {
			return "", err
		}
		return offlineCA.GenerateToken(ctx, typ, subject, sans, notBefore, notAfter)
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

	return generateToken(typ, subject, sans, kid, issuer, audience, root, notBefore, notAfter, jwk)
}

func provisionerPrompt(ctx *cli.Context, provisioners provisioner.List) (provisioner.Interface, error) {
	// Filter by type
	provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
		switch p.GetType() {
		case provisioner.TypeJWK, provisioner.TypeOIDC:
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
