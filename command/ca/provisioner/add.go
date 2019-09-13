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

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add one or more provisioners the CA configuration",
		UsageText: `**step ca provisioner add** <name> <jwk-file> [<jwk-file> ...]
**--ca-config**=<file> [**--type**=JWK]  [**--create**] [**--password-file**=<file>]

**step ca provisioner add** <name> **--type**=OIDC **--ca-config**=<file>
[**--client-id**=<id>] [**--client-secret**=<secret>]
[**--configuration-endpoint**=<url>] [**--domain**=<domain>]
[**--admin**=<email>]...

**step ca provisioner add** <name> **--type**=[AWS|Azure|GCP] **--ca-config**=<file>
[**--aws-account**=<id>]
[**--gcp-service-account**=<name>] [**--gcp-project**=<name>]
[**--azure-tenant**=<id>] [**--azure-resource-group**=<name>]
[**--instance-age**=<duration>] [**--disable-custom-sans**] [**--disable-trust-on-first-use**]

**step ca provisioner add** <name> **--type**=ACME **--ca-config**=<file>`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-config",
				Usage: "The <file> containing the CA configuration.",
			},
			cli.StringFlag{
				Name:  "type",
				Value: provisioner.TypeJWK.String(),
				Usage: `The <type> of provisioner to create. Type is a case-insensitive string
and must be one of:
    **JWK**
    : Uses an JWK key pair to sign bootstrap tokens. (default)

    **OIDC**
    : Uses an OpenID Connect provider to sign bootstrap tokens.

    **AWS**
    : Uses Amazon AWS instance identity documents.

    **GCP**
    : Use Google instance identity tokens.

    **Azure**
    : Uses Microsoft Azure identity tokens.

    **ACME**
    : Uses the ACME protocol to create certificates.
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
			cli.StringSliceFlag{
				Name: "aws-account",
				Usage: `The AWS account <id> used to validate the identity documents.
Use the flag multiple times to configure multiple accounts.`,
			},
			cli.StringSliceFlag{
				Name: "gcp-service-account",
				Usage: `The Google service account <email> or <id> used to validate the identity tokens.
Use the flag multiple times to configure multiple service accounts.`,
			},
			cli.StringSliceFlag{
				Name: "gcp-project",
				Usage: `The Google project <id> used to validate the identity tokens.
Use the flag multipl etimes to configure multiple projects`,
			},
			cli.StringFlag{
				Name:  "azure-tenant",
				Usage: `The Microsoft Azure tenant <id> used to validate the identity tokens.`,
			},
			cli.StringSliceFlag{
				Name: "azure-resource-group",
				Usage: `The Microsoft Azure resource group <name> used to validate the identity tokens.
Use the flag multipl etimes to configure multiple resource groups`,
			},
			cli.DurationFlag{
				Name: "instance-age",
				Usage: `The maximum <duration> to grant a certificate in AWS and GCP provisioners.
A <duration> is sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.BoolFlag{
				Name: "disable-custom-sans",
				Usage: `On cloud provisioners, if anabled only the internal DNS and IP will be added as a SAN.
By default it will accept any SAN in the CSR.`,
			},
			cli.BoolFlag{
				Name: "disable-trust-on-first-use,disable-tofu",
				Usage: `On cloud provisioners, if enabled multiple sign request for this provisioner
with the same instance will be accepted. By default only the first request
will be accepted.`,
			},
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
'''

Add an AWS provisioner on one account with a one hour of intance age:
'''
$ step ca provisioner add Amazon --type AWS --ca-config ca.json \
  --aws-account 123456789 --instance-age 1h
'''

Add an GCP provisioner with two service accounts and two project ids:
'''
$ step ca provisioner add Google --type GCP --ca-config ca.json \
  --gcp-service-account 1234567890-compute@developer.gserviceaccount.com \
  --gcp-service-account 9876543210-compute@developer.gserviceaccount.com \
  --gcp-project identity --gcp-project accounting
'''

Add an Azure provisioner with two service groups:
'''
$ step ca provisioner add Azure --type Azure --ca-config ca.json \
  --azure-tenant bc9043e2-b645-4c1c-a87a-78f8644bfe57 \
  --azure-resource-group identity --azure-resource-group accounting
'''

Add an GCP provisioner that will only accept the SANs provided in the identity token:
'''
$ step ca provisioner add Google --type GCP --ca-config ca.json \
  --disable-custom-sans --gcp-project internal
'''

Add an AWS provisioner that will only accept the SANs provided in the identity
document and will allow multiple certificates from the same instance:
'''
$ step ca provisioner add Amazon --type AWS --ca-config ca.json \
  --aws-account 123456789 --disable-custom-sans --disable-trust-on-first-use

Add an ACME provisioner.
'''
$ step ca provisioner add acme-smallstep --type ACME --ca-config ca.json
'''`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if ctx.NArg() == 0 {
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

	typ, err := parseProvisionerType(ctx)
	if err != nil {
		return err
	}

	provMap := make(map[string]bool)
	for _, p := range c.AuthorityConfig.Provisioners {
		provMap[p.GetID()] = true
	}

	var list provisioner.List
	switch typ {
	case provisioner.TypeJWK:
		list, err = addJWKProvisioner(ctx, name, provMap)
	case provisioner.TypeOIDC:
		list, err = addOIDCProvisioner(ctx, name, provMap)
	case provisioner.TypeAWS:
		list, err = addAWSProvisioner(ctx, name, provMap)
	case provisioner.TypeAzure:
		list, err = addAzureProvisioner(ctx, name, provMap)
	case provisioner.TypeGCP:
		list, err = addGCPProvisioner(ctx, name, provMap)
	case provisioner.TypeACME:
		list, err = addACMEProvisioner(ctx, name, provMap)
	default:
		return errors.Errorf("unknown type %s: this should not happen", typ)
	}

	if err != nil {
		return err
	}

	c.AuthorityConfig.Provisioners = append(c.AuthorityConfig.Provisioners, list...)
	return c.Save(config)
}

func addJWKProvisioner(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
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
			Type:         provisioner.TypeJWK.String(),
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
			Type: provisioner.TypeJWK.String(),
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

func addOIDCProvisioner(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
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
		Type:                  provisioner.TypeOIDC.String(),
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

func addAWSProvisioner(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
	d, err := parseIntaceAge(ctx)
	if err != nil {
		return nil, err
	}

	p := &provisioner.AWS{
		Type:                   provisioner.TypeAWS.String(),
		Name:                   name,
		Accounts:               ctx.StringSlice("aws-account"),
		DisableCustomSANs:      ctx.Bool("disable-custom-sans"),
		DisableTrustOnFirstUse: ctx.Bool("disable-trust-on-first-use"),
		InstanceAge:            d,
	}

	// Check for duplicates
	if _, ok := provMap[p.GetID()]; !ok {
		provMap[p.GetID()] = true
	} else {
		return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with type=AWS and name=%s", p.GetName())
	}

	list = append(list, p)
	return
}

func addAzureProvisioner(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
	tenantID := ctx.String("azure-tenant")
	if tenantID == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "type", ctx.String("type"), "azure-tenant")
	}

	p := &provisioner.Azure{
		Type:                   provisioner.TypeAzure.String(),
		Name:                   name,
		TenantID:               tenantID,
		ResourceGroups:         ctx.StringSlice("azure-resource-group"),
		DisableCustomSANs:      ctx.Bool("disable-custom-sans"),
		DisableTrustOnFirstUse: ctx.Bool("disable-trust-on-first-use"),
	}

	// Check for duplicates
	if _, ok := provMap[p.GetID()]; !ok {
		provMap[p.GetID()] = true
	} else {
		return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with type=Azure and name=%s", p.GetName())
	}

	list = append(list, p)
	return
}

func addGCPProvisioner(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
	d, err := parseIntaceAge(ctx)
	if err != nil {
		return nil, err
	}

	p := &provisioner.GCP{
		Type:                   provisioner.TypeGCP.String(),
		Name:                   name,
		ServiceAccounts:        ctx.StringSlice("gcp-service-account"),
		ProjectIDs:             ctx.StringSlice("gcp-project"),
		DisableCustomSANs:      ctx.Bool("disable-custom-sans"),
		DisableTrustOnFirstUse: ctx.Bool("disable-trust-on-first-use"),
		InstanceAge:            d,
	}

	// Check for duplicates
	if _, ok := provMap[p.GetID()]; !ok {
		provMap[p.GetID()] = true
	} else {
		return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with type=GCP and name=%s", p.GetName())
	}

	list = append(list, p)
	return
}

func addACMEProvisioner(ctx *cli.Context, name string, provMap map[string]bool) (list provisioner.List, err error) {
	p := &provisioner.ACME{
		Type: provisioner.TypeACME.String(),
		Name: name,
	}

	// Check for duplicates
	if _, ok := provMap[p.GetID()]; !ok {
		provMap[p.GetID()] = true
	} else {
		return nil, errors.Errorf("duplicated provisioner: CA config already contains a provisioner with ID==%s", p.GetID())
	}

	list = append(list, p)
	return
}

func parseIntaceAge(ctx *cli.Context) (provisioner.Duration, error) {
	age := ctx.Duration("instance-age")
	if age == 0 {
		return provisioner.Duration{}, nil
	}
	if age < 0 {
		return provisioner.Duration{}, errs.MinSizeFlag(ctx, "instance-age", "0s")
	}
	return provisioner.Duration{Duration: age}, nil
}

func parseProvisionerType(ctx *cli.Context) (provisioner.Type, error) {
	typ := ctx.String("type")
	switch strings.ToLower(typ) {
	case "", "jwk":
		return provisioner.TypeJWK, nil
	case "oidc":
		return provisioner.TypeOIDC, nil
	case "gcp":
		return provisioner.TypeGCP, nil
	case "aws":
		return provisioner.TypeAWS, nil
	case "azure":
		return provisioner.TypeAzure, nil
	case "acme":
		return provisioner.TypeACME, nil
	default:
		return 0, errs.InvalidFlagValue(ctx, "type", typ, "JWK, OIDC, AWS, Azure, GCP")
	}
}
