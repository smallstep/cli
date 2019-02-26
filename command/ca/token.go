package ca

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

type provisionersSelect struct {
	Name   string
	Issuer string
	JWK    jose.JSONWebKey
}

func newTokenCommand() cli.Command {
	return cli.Command{
		Name:   "token",
		Action: command.ActionFunc(newTokenAction),
		Usage:  "generate an OTT granting access to the CA",
		UsageText: `**step ca token** <subject>
		[--**kid**=<kid>] [--**issuer**=<issuer>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
		[**--password-file**=<file>] [**--output-file**=<file>] [**--key**=<file>]
		[**--san**=<SAN>] [**--offline**]`,
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

Get a new token using the simple offline mode, requires the file ca.json
created with **step ca init**:
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
				Usage: `The private key <file> used to sign the JWT. This is usually downloaded from
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
			caConfigFlag,
			flags.Force,
		},
	}
}

func newTokenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	subject := ctx.Args().Get(0)
	kid := ctx.String("kid")
	issuer := ctx.String("issuer")
	passwordFile := ctx.String("password-file")
	outputFile := ctx.String("output-file")
	keyFile := ctx.String("key")
	offline := ctx.Bool("offline")
	sans := ctx.StringSlice("san")

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
		token, err = offlineTokenFlow(ctx, subject)
		if err != nil {
			return err
		}
	} else {
		token, err = newTokenFlow(ctx, subject, sans, caURL, root, kid, issuer, passwordFile, keyFile, notBefore, notAfter)
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
func parseAudience(ctx *cli.Context) (string, error) {
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
		audience.Scheme = "https"
		audience = audience.ResolveReference(&url.URL{Path: "/1.0/sign"})
		return audience.String(), nil
	default:
		return "", errs.InvalidFlagValue(ctx, "ca-url", caURL, "")
	}
}

// generateToken generates a provisioning or bootstrap token with the given
// parameters.
func generateToken(sub string, sans []string, kid, iss, aud, root string, notBefore, notAfter time.Time, jwk *jose.JSONWebKey) (string, error) {
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
	// If there are no SANs then add the 'subject' (common-name) as the only SAN.
	if len(sans) == 0 {
		sans = []string{sub}
	}

	tokOptions = append(tokOptions, token.WithSANS(sans))
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
func newTokenFlow(ctx *cli.Context, subject string, sans []string, caURL, root, kid, issuer, passwordFile, keyFile string, notBefore, notAfter time.Time) (string, error) {
	// Get audience from ca-url
	audience, err := parseAudience(ctx)
	if err != nil {
		return "", err
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return "", err
	}

	if len(provisioners) == 0 {
		return "", errors.New("cannot create a new token: the CA does not have any provisioner configured")
	}

	// Filter by kid
	if len(kid) != 0 {
		provisioners = provisionerFilter(provisioners, func(p *authority.Provisioner) bool {
			return p.Key.KeyID == kid
		})
		if len(provisioners) == 0 {
			return "", errs.InvalidFlagValue(ctx, "kid", kid, "")
		}
	}

	// Filter by issuer (provisioner name)
	if len(issuer) != 0 {
		provisioners = provisionerFilter(provisioners, func(p *authority.Provisioner) bool {
			return p.Name == issuer
		})
		if len(provisioners) == 0 {
			return "", errs.InvalidFlagValue(ctx, "issuer", issuer, "")
		}
	}

	if len(provisioners) == 1 {
		kid = provisioners[0].Key.KeyID
		issuer = provisioners[0].Name
		// Prints kid/issuer used
		if err := ui.PrintSelected("Key ID", kid+" ("+issuer+")"); err != nil {
			return "", err
		}
	} else {
		var items []*provisionersSelect
		for _, p := range provisioners {
			items = append(items, &provisionersSelect{
				Name:   p.Key.KeyID + " (" + p.Name + ")",
				Issuer: p.Name,
				JWK:    *p.Key,
			})
		}
		i, _, err := ui.Select("What provisioner key do you want to use?", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Key ID")))
		if err != nil {
			return "", err
		}
		kid = items[i].JWK.KeyID
		issuer = items[i].Issuer
	}

	var opts []jose.Option
	if len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}

	var jwk *jose.JSONWebKey
	if len(keyFile) == 0 {
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

	return generateToken(subject, sans, kid, issuer, audience, root, notBefore, notAfter, jwk)
}

func offlineTokenFlow(ctx *cli.Context, subject string) (string, error) {
	caConfig := ctx.String("ca-config")
	if caConfig == "" {
		return "", errs.InvalidFlagValue(ctx, "ca-config", "", "")
	}

	// Using the offline CA
	if utils.FileExists(caConfig) {
		offlineCA, err := newOfflineCA(caConfig)
		if err != nil {
			return "", err
		}

		return offlineCA.GenerateToken(ctx, subject)
	}

	kid := ctx.String("kid")
	issuer := ctx.String("issuer")
	keyFile := ctx.String("key")
	passwordFile := ctx.String("password-file")
	sans := ctx.StringSlice("san")

	notBefore, notAfter, err := parseValidity(ctx)
	if err != nil {
		return "", err
	}

	// Require kid, issuer and keyFile if ca.json does not exists
	switch {
	case len(kid) == 0:
		return "", errs.RequiredWithFlag(ctx, "offline", "kid")
	case len(issuer) == 0:
		return "", errs.RequiredWithFlag(ctx, "offline", "issuer")
	case len(keyFile) == 0:
		return "", errs.RequiredWithFlag(ctx, "offline", "key")
	}

	// Get audience from ca-url
	audience, err := parseAudience(ctx)
	if err != nil {
		return "", err
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if utils.FileExists(root) {
			return "", errs.RequiredFlag(ctx, "root")
		}
	}

	var opts []jose.Option
	if len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}
	jwk, err := jose.ParseKey(keyFile, opts...)
	if err != nil {
		return "", err
	}

	return generateToken(subject, sans, kid, issuer, audience, root, notBefore, notAfter, jwk)
}

// provisionerFilter returns a slice of provisioners that pass the given filter.
func provisionerFilter(provisioners []*authority.Provisioner, f func(*authority.Provisioner) bool) []*authority.Provisioner {
	var result []*authority.Provisioner
	for _, p := range provisioners {
		if f(p) {
			result = append(result, p)
		}
	}
	return result
}
