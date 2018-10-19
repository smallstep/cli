package ca

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

const defaultSignatureAlgorithm = "ES256"

type provisionersSelect struct {
	Name   string
	Issuer string
	JWK    jose.JSONWebKey
}

func newTokenCommand() cli.Command {
	return cli.Command{
		Name:   "new-token",
		Action: cli.ActionFunc(newTokenAction),
		Usage:  "generates an OTT granting access to the CA",
		UsageText: `**step ca new-token** <hostname>
		[--**kid**=<kid>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--password-file**=<file>] [**--output-file**=<file>]`,
		Description: `**step ca new-token** command generates a one-time token granting access to the
certificates authority

## POSITIONAL ARGUMENTS

<hostname>
:  The DNS or IP address that will be set by the certificate authority.

## EXAMPLES

 Most of the following examples assumes that the **--ca-url** and **--root** are
 set using environment variables or the default configuration file in
 <$STEPPATH/config/defaults.json>.

Get a new token for a DNS:
'''
$ step ca new-token internal.example.com
'''

Get a new token for an IP address:
'''
$ step ca new-token 192.168.10.10
'''

Get a new token that would be valid not, but expires in 30 minutes:
'''
$ step ca new-token --not-after 30m internal.example.com
'''

Get a new token that is not valid for 30 and expires 5 minutes after that:
'''
$ step ca new-token --not-before 30m --not-after 35m internal.example.com
'''

Get a new token for a specific provisioner kid, ca-url and root:
'''
$ step ca new-token internal.example.com \
    --kid 4vn46fbZT68Uxfs9LBwHkTvrjEvxQqx-W8nnE-qDjts \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt internal.example.com
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "kid",
				Usage: "The provisioner <kid> to use.",
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
			cli.StringFlag{
				Name: "password-file",
				Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
			},
			cli.StringFlag{
				Name:  "output-file",
				Usage: "The destination <file> of the generated one-time token.",
			},
			cli.StringFlag{
				Name: "not-before",
				Usage: `The <time|duration> set in the NotBefore (nbf) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringFlag{
				Name: "not-after",
				Usage: `The <time|duration> set in the Expiration (exp) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
		},
	}
}

func newTokenAction(ctx *cli.Context) error {
	var issuer string
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	subject := ctx.Args().Get(0)
	root := ctx.String("root")
	kid := ctx.String("kid")
	passwordFile := ctx.String("password-file")
	outputFile := ctx.String("output-file")

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	audience, err := url.Parse(caURL)
	if err != nil || audience.Scheme != "https" {
		return errs.InvalidFlagValue(ctx, "ca-url", caURL, "")
	}
	audience = audience.ResolveReference(&url.URL{Path: "/1.0/sign"})

	// parse times or durations
	notBefore, ok := parseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := parseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return err
	}
	if len(provisioners) == 0 {
		return errors.New("cannot create a new token: the CA does not have any provisioner configured")
	}

	var items []*provisionersSelect
	for _, p := range provisioners {
		items = append(items, &provisionersSelect{
			Name:   p.Key.KeyID + " (" + p.Issuer + ")",
			Issuer: p.Issuer,
			JWK:    *p.Key,
		})
	}

	if len(kid) == 0 {
		i, _, err := ui.Select("What provisioner key do you want to use?", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Key ID")))
		if err != nil {
			return errors.Wrap(err, "error running prompt")
		}

		kid = items[i].JWK.KeyID
		issuer = items[i].Issuer
	} else {
		var found bool
		for _, item := range items {
			if kid == item.JWK.KeyID {
				found = true
				issuer = item.Issuer
				break
			}
		}
		if !found {
			return errs.InvalidFlagValue(ctx, "kid", kid, "")
		}
	}

	encrypted, err := pki.GetProvisionerKey(caURL, root, kid)
	if err != nil {
		return err
	}

	var opts []jose.Option
	if len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}

	decrypted, err := jose.Decrypt("Please enter the password to decrypt the provisioner key:", []byte(encrypted), opts...)
	if err != nil {
		return err
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &jwk); err != nil {
		return errors.Wrap(err, "error unmarshalling provisioning key")
	}

	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return err
	}

	// Generate token
	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithIssuer(issuer),
		token.WithAudience(audience.String()),
	}
	if len(root) > 0 {
		tokOptions = append(tokOptions, token.WithRootCA(root))
	}
	if len(caURL) > 0 {
		tokOptions = append(tokOptions, token.WithCA(caURL))
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

	tok, err := provision.New(subject, tokOptions...)
	if err != nil {
		return err
	}

	token, err := tok.SignedString(jwk.Algorithm, jwk.Key)
	if err != nil {
		return err
	}

	if len(outputFile) > 0 {
		return utils.WriteFile(outputFile, []byte(token), 0600)
	}
	fmt.Println(token)
	return nil
}

func parseTimeOrDuration(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, true
	}

	var t time.Time
	if err := t.UnmarshalText([]byte(s)); err != nil {
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, false
		}
		t = time.Now().Add(d)
	}
	return t, true
}
