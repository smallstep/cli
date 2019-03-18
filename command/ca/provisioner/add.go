package provisioner

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

const (
	jwkType  = "JWK"
	oidcType = "OIDC"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add one or more provisioners the CA configuration",
		UsageText: `**step ca provisioner add** <name> <jwk-file> [<jwk-file> ...]
		[**--ca-config**=<file>] [**--create**] [**--password-file**=<file>]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-config",
				Usage: "The <file> containing the CA configuration.",
			},
			cli.StringFlag{
				Name:  "type",
				Value: jwkType,
				Usage: `The <type> of provisioner to create. Type is a case-insensitive string
and must be one of:
    **JWK**
    : Uses an JWK key pair to sign bootstrap tokens. (default)

    **OIDC**
    : Uses an OpenID Connect provider to sign bootstrap tokens.
`,
			},
			cli.BoolFlag{
				Name: "create",
				Usage: `Create a new ECDSA key pair using curve P-256 and populate a new JWK
provisioner with it.`,
			},
			cli.StringFlag{
				Name:  "client-id",
				Usage: `The <id> used to validate the audience in an OpenID Connect token.`,
			},
			cli.StringFlag{
				Name:  "client-secret",
				Usage: `The <secret> used to obtain the OpenID Connect tokens.`,
			},
			cli.StringFlag{
				Name:  "configuration-endpoint",
				Usage: `OpenID Connect configuration <url>.`,
			},
			cli.StringSliceFlag{
				Name: "admin",
				Usage: `The <email> of an admin user in an OpenID Connect provisioner, this user
will not have restrictions in the certificates to sign. Use the
'--admin' flag multiple times to configure multiple administrators.`,
			},
			cli.StringSliceFlag{
				Name: "domain",
				Usage: `The <domain> used to validate the email claim in an OpenID Connect provisioner.
Use the '--domain' flag multiple times to configure multiple domains.`,
			},
			flags.PasswordFile,
		},
		Description: `**step ca provisioner add** adds one or more provisioners
to the configuration and writes the new configuration back to the CA config.

## POSITIONAL ARGUMENTS

<name>
: The name of the provisioners, if a list of JWK files are passed, this name 
will be linked to all the keys.

<jwk-path>
: List of private (or public) keys in JWK or PEM format.

## EXAMPLES

Add a single JWK provisioner:
'''
$ step ca provisioner add max@smallstep.com ./max-laptop.jwk --ca-config ca.json
'''

Add a single JWK provisioner using an auto-generated asymmetric key pair:
'''
$ step ca provisioner add max@smallstep.com --ca-config ca.json \
--create
'''

Add a list of provisioners for a single name:
'''
$ step ca provisioner add max@smallstep.com ./max-laptop.jwk ./max-phone.pem ./max-work.pem \
--ca-config ca.json
'''

Add a single OIDC provisioner:
'''
$ step ca provisioner add Google --type oidc --ca-config ca.json \
  --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
  --configuration-endpoint https://accounts.google.com/.well-known/openid-configuration
'''

Add an OIDC provisioner with two administrators:
'''
$ step ca provisioner add Google --type oidc --ca-config ca.json \
  --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
  --client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
  --configuration-endpoint https://accounts.google.com/.well-known/openid-configuration \
  --admin mariano@smallstep.com --admin max@smallstep.com \
  --domain smallstep.com
'''	`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if ctx.NArg() < 1 {
		return errs.TooFewArguments(ctx)
	}

	args := ctx.Args()
	name := args[0]

	config := ctx.String("ca-config")
	if len(config) == 0 {
		return errs.RequiredFlag(ctx, "ca-config")
	}

	c, err := authority.LoadConfiguration(config)
	if err != nil {
		return errors.Wrapf(err, "error loading configuration")
	}

	typ := strings.ToUpper(ctx.String("type"))
	if typ != jwkType && typ != oidcType {
		return errs.InvalidFlagValue(ctx, "type", typ, "JWK, OIDC")
	}

	provMap := make(map[string]bool)
	for _, p := range c.AuthorityConfig.Provisioners {
		provMap[p.GetID()] = true
	}

	var list provisioner.List
	switch typ {
	case jwkType:
		if list, err = addJWKProvider(ctx, name, provMap); err != nil {
			return err
		}
	case oidcType:
		if list, err = addOIDCProvider(ctx, name, provMap); err != nil {
			return err
		}
	default:
		return errors.Errorf("unknown type %s: this should not happen", typ)
	}

	c.AuthorityConfig.Provisioners = append(c.AuthorityConfig.Provisioners, list...)
	return c.Save(config)
}

func addJWKProvider(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
	var password string
	if passwordFile := ctx.String("password-file"); len(passwordFile) > 0 {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return nil, err
		}
	}

	if ctx.Bool("create") {
		if ctx.NArg() > 1 {
			return nil, errs.IncompatibleFlag(ctx, "create", "<jwk-path> positional arg")
		}
		pass, err := ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]", ui.WithValue(password))
		if err != nil {
			return nil, err
		}
		jwk, jwe, err := jose.GenerateDefaultKeyPair(pass)
		if err != nil {
			return nil, err
		}
		encryptedKey, err := jwe.CompactSerialize()
		if err != nil {
			return nil, errors.Wrap(err, "error serializing private key")
		}

		// Create provisioner
		p := &provisioner.JWK{
			Type:         jwkType,
			Name:         name,
			Key:          jwk,
			EncryptedKey: encryptedKey,
		}
		// Check for duplicates
		if _, ok := provMap[p.GetID()]; !ok {
			provMap[p.GetID()] = true
		} else {
			return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with name=%s and kid=%s", name, jwk.KeyID)
		}
		list = append(list, p)
		return list, nil
	}

	// Add multiple provisioners using JWK files.
	if ctx.NArg() < 2 {
		return nil, errs.TooFewArguments(ctx)
	}

	jwkFiles := ctx.Args()[1:]
	for _, filename := range jwkFiles {
		jwk, err := jose.ParseKey(filename)
		if err != nil {
			return nil, errs.FileError(err, filename)
		}
		// Only use asymmetric cryptography
		if _, ok := jwk.Key.([]byte); ok {
			return nil, errors.New("invalid JWK: a symmetric key cannot be used as a provisioner")
		}
		// Create kid if not present
		if len(jwk.KeyID) == 0 {
			jwk.KeyID, err = jose.Thumbprint(jwk)
			if err != nil {
				return nil, err
			}
		}
		key := jwk.Public()

		// Initialize provisioner and check for duplicates
		p := &provisioner.JWK{
			Type: jwkType,
			Name: name,
			Key:  &key,
		}
		if _, ok := provMap[p.GetID()]; !ok {
			provMap[p.GetID()] = true
		} else {
			return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with name=%s and kid=%s", name, jwk.KeyID)
		}

		// Encrypt JWK
		if !jwk.IsPublic() {
			jwe, err := jose.EncryptJWK(jwk)
			if err != nil {
				return nil, err
			}
			encryptedKey, err := jwe.CompactSerialize()
			if err != nil {
				return nil, errors.Wrap(err, "error serializing private key")
			}
			p.EncryptedKey = encryptedKey
		}

		list = append(list, p)
	}
	return list, nil
}

func addOIDCProvider(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
	clientID := ctx.String("client-id")
	if len(clientID) == 0 {
		return nil, errs.RequiredWithFlagValue(ctx, "type", ctx.String("type"), "client-id")
	}

	confURL := ctx.String("configuration-endpoint")
	if len(confURL) == 0 {
		return nil, errs.RequiredWithFlagValue(ctx, "type", ctx.String("type"), "configuration-endpoint")
	}
	u, err := url.Parse(confURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errs.InvalidFlagValue(ctx, "configuration-endpoint", confURL, "")
	}

	// Create provisioner
	p := &provisioner.OIDC{
		Type:                  oidcType,
		Name:                  name,
		ClientID:              clientID,
		ClientSecret:          ctx.String("client-secret"),
		ConfigurationEndpoint: confURL,
		Admins:                ctx.StringSlice("admin"),
		Domains:               ctx.StringSlice("domain"),
	}
	// Check for duplicates
	if _, ok := provMap[p.GetID()]; !ok {
		provMap[p.GetID()] = true
	} else {
		return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with name=%s and client-id=%s", p.GetName(), p.GetID())
	}
	list = append(list, p)
	return
}
