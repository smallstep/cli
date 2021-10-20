package provisionerbeta

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/encoding/protojson"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add a provisioner",
		UsageText: `**step beta ca provisioner add** <name> **--type**=JWK [**--public-key**=<file>]
[**--private-key**=<file>] [**--create**] [**--password-file**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

**step beta ca provisioner add** <name> **--type**=OIDC
[**--client-id**=<id>] [**--client-secret**=<secret>]
[**--configuration-endpoint**=<url>] [**--domain**=<domain>]
[**--admin**=<email>]...
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]


**step beta ca provisioner add** <name> **--type**=X5C **--x5c-root**=<file>
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

**step beta ca provisioner add** <name> **--type**=SSHPOP
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

**step beta ca provisioner add** <name> **--type**=K8SSA [**--public-key**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

**step beta ca provisioner add** <name> **--type**=[AWS|Azure|GCP]
[**--aws-account**=<id>] [**--gcp-service-account**=<name>] [**--gcp-project**=<name>]
[**--azure-tenant**=<id>] [**--azure-resource-group**=<name>]
[**--instance-age**=<duration>] [**--iid-roots**=<file>]
[**--disable-custom-sans**] [**--disable-trust-on-first-use**]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

**step beta ca provisioner add** <name> **--type**=ACME [**--force-cn**]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "type",
				Value: provisioner.TypeJWK.String(),
				Usage: `The <type> of provisioner to create.

: <type> is a case-insensitive string and must be one of:

    **JWK**
    : Uses an JWK key pair to sign provisioning tokens. (default)

    **OIDC**
    : Uses an OpenID Connect provider to sign provisioning tokens.

    **AWS**
    : Uses Amazon AWS instance identity documents.

    **GCP**
    : Use Google instance identity tokens.

    **Azure**
    : Uses Microsoft Azure identity tokens.

    **ACME**
    : Uses the ACME protocol to create certificates.

    **X5C**
    : Uses an X509 Certificate / private key pair to sign provisioning tokens.

    **K8SSA**
    : Uses Kubernetes Service Account tokens.

    **SSHPOP**
    : Uses an SSH Certificate / private key pair to sign provisioning tokens.`},
			x509TemplateFlag,
			x509TemplateDataFlag,
			sshTemplateFlag,
			sshTemplateDataFlag,
			x509MinDurFlag,
			x509MaxDurFlag,
			x509DefaultDurFlag,
			sshUserMinDurFlag,
			sshUserMaxDurFlag,
			sshUserDefaultDurFlag,
			sshHostMinDurFlag,
			sshHostMaxDurFlag,
			sshHostDefaultDurFlag,
			disableRenewalFlag,
			enableX509Flag,
			enableSSHFlag,

			// JWK provisioner flags
			cli.BoolFlag{
				Name:  "create",
				Usage: `Create the JWK key pair for the provisioner.`,
			},
			cli.StringFlag{
				Name:  "private-key",
				Usage: `The <file> containing the JWK private key.`,
			},
			cli.StringFlag{
				Name: "public-key",
				Usage: `The <file> containing the JWK public key. Or, a <file>
containing one or more PEM formatted keys, if used with the K8SSA provisioner.`,
			},

			// OIDC provisioner flags
			cli.StringFlag{
				Name:  "client-id",
				Usage: `The <id> used to validate the audience in an OpenID Connect token.`,
			},
			cli.StringFlag{
				Name:  "client-secret",
				Usage: `The <secret> used to obtain the OpenID Connect tokens.`,
			},
			cli.StringFlag{
				Name:  "listen-address",
				Usage: `The callback <address> used in the OpenID Connect flow (e.g. \":10000\")`,
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
				Name: "group",
				Usage: `The <group> list used to validate the groups extenstion in an OpenID Connect token.
Use the '--group' flag multiple times to configure multiple groups.`,
			},
			cli.StringFlag{
				Name:  "tenant-id",
				Usage: `The <tenant-id> used to replace the templatized {tenantid} in the OpenID Configuration.`,
			},

			// X5C provisioner flags
			cli.StringFlag{
				Name: "x5c-root",
				Usage: `Root certificate (chain) <file> used to validate the signature on X5C
provisioning tokens.`,
			},

			// ACME provisioner flags
			forceCNFlag,

			// Cloud provisioner flags
			awsAccountFlag,
			azureTenantFlag,
			azureResourceGroupFlag,
			gcpServiceAccountFlag,
			gcpProjectFlag,
			instanceAgeFlag,
			iidRootsFlag,
			disableCustomSANsFlag,
			disableTOFUFlag,

			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step ca provisioner add** adds a provisioner to the CA configuration.

## POSITIONAL ARGUMENTS

<name>
: The name of the provisioner.

## EXAMPLES

Create a JWK provisioner with newly generated keys and a template for x509 certificates:
'''
step beta ca provisioner add cicd --type JWK --create --x509-template ./templates/example.tpl
'''

Create a JWK provisioner with duration claims:
'''
step beta ca provisioner add cicd --type JWK --create --x509-min-dur 20m --x509-default-dur 48h --ssh-user-min-dur 17m --ssh-host-default-dur 16h
'''

Create a JWK provisioner with existing keys:
'''
step beta ca provisioner add jane@doe.com --type JWK --public-key jwk.pub --private-key jwk.priv
'''

Create an OIDC provisioner:
'''
step beta ca provisioner add Google --type OIDC --ssh \
	--client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
	--client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
	--configuration-endpoint https://accounts.google.com/.well-known/openid-configuration
'''

Create an X5C provisioner:
'''
step beta ca provisioner add x5c --type X5C --x5c-root x5c_ca.crt
'''

Create an ACME provisioner:
'''
step beta ca provisioner add acme --type ACME
'''

Create an K8SSA provisioner:
'''
step beta ca provisioner add kube --type K8SSA --ssh --public-key key.pub
'''

Create an SSHPOP provisioner for renewing SSH host certificates:")
'''
step beta ca provisioner add sshpop --type SSHPOP
'''

Create an Azure provisioner with two service groups:
'''
$ step beta ca provisioner add Azure --type Azure \
  --azure-tenant bc9043e2-b645-4c1c-a87a-78f8644bfe57 \
  --azure-resource-group identity --azure-resource-group accounting
'''

Create an GCP provisioner that will only accept the SANs provided in the identity token:
'''
$ step beta ca provisioner add Google --type GCP \
  --disable-custom-sans --gcp-project internal
'''

Create an AWS provisioner that will only accept the SANs provided in the identity
document and will allow multiple certificates from the same instance:
'''
$ step beta ca provisioner add Amazon --type AWS \
  --aws-account 123456789 --disable-custom-sans --disable-trust-on-first-use
'''

Create an AWS provisioner that will use a custom certificate to validate the instance
identity documents:
'''
$ step beta ca provisioner add Amazon --type AWS \
  --aws-account 123456789 --iid-roots $(step path)/certs/aws.crt
'''`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	x509TemplateFile := ctx.String("x509-template")
	x509TemplateDataFile := ctx.String("x509-template-data")
	sshTemplateFile := ctx.String("ssh-template")
	sshTemplateDataFile := ctx.String("ssh-template-data")

	args := ctx.Args()

	typ := ctx.String("type")

	p := &linkedca.Provisioner{
		Name: args.Get(0),
	}

	// Read x509 template if passed
	p.X509Template = &linkedca.Template{}
	if x509TemplateFile != "" {
		b, err := utils.ReadFile(x509TemplateFile)
		if err != nil {
			return err
		}
		p.X509Template.Template = b
	}
	if x509TemplateDataFile != "" {
		b, err := utils.ReadFile(x509TemplateDataFile)
		if err != nil {
			return err
		}
		p.X509Template.Data = b
	}
	// Read ssh template if passed
	p.SshTemplate = &linkedca.Template{}
	if sshTemplateFile != "" {
		b, err := utils.ReadFile(sshTemplateFile)
		if err != nil {
			return err
		}
		p.SshTemplate.Template = b
	}
	if sshTemplateDataFile != "" {
		b, err := utils.ReadFile(sshTemplateDataFile)
		if err != nil {
			return err
		}
		p.SshTemplate.Data = b
	}

	p.Claims = &linkedca.Claims{
		X509: &linkedca.X509Claims{
			Durations: &linkedca.Durations{
				Min:     ctx.String("x509-min-dur"),
				Max:     ctx.String("x509-max-dur"),
				Default: ctx.String("x509-default-dur"),
			},
			Enabled: !(ctx.IsSet("x509") && !ctx.Bool("x509")),
		},
		Ssh: &linkedca.SSHClaims{
			UserDurations: &linkedca.Durations{
				Min:     ctx.String("ssh-user-min-dur"),
				Max:     ctx.String("ssh-user-max-dur"),
				Default: ctx.String("ssh-user-default-dur"),
			},
			HostDurations: &linkedca.Durations{
				Min:     ctx.String("ssh-host-min-dur"),
				Max:     ctx.String("ssh-host-max-dur"),
				Default: ctx.String("ssh-host-default-dur"),
			},
			Enabled: !(ctx.IsSet("ssh") && !ctx.Bool("ssh")),
		},
		DisableRenewal: ctx.Bool("disable-renewal"),
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	switch typ {
	case linkedca.Provisioner_JWK.String():
		p.Type = linkedca.Provisioner_JWK
		p.Details, err = createJWKDetails(ctx)
	case linkedca.Provisioner_ACME.String():
		p.Type = linkedca.Provisioner_ACME
		p.Details, err = createACMEDetails(ctx)
	case linkedca.Provisioner_SSHPOP.String():
		p.Type = linkedca.Provisioner_SSHPOP
		p.Details, err = createSSHPOPDetails(ctx)
	case linkedca.Provisioner_X5C.String():
		p.Type = linkedca.Provisioner_X5C
		p.Details, err = createX5CDetails(ctx)
	case linkedca.Provisioner_K8SSA.String():
		p.Type = linkedca.Provisioner_K8SSA
		p.Details, err = createK8SSADetails(ctx)
	case linkedca.Provisioner_OIDC.String():
		p.Type = linkedca.Provisioner_OIDC
		p.Details, err = createOIDCDetails(ctx)
	case linkedca.Provisioner_AWS.String():
		p.Type = linkedca.Provisioner_AWS
		p.Details, err = createAWSDetails(ctx)
	case linkedca.Provisioner_AZURE.String():
		p.Type = linkedca.Provisioner_AZURE
		p.Details, err = createAzureDetails(ctx)
	case linkedca.Provisioner_GCP.String():
		p.Type = linkedca.Provisioner_GCP
		p.Details, err = createGCPDetails(ctx)
	// TODO add SCEP provisioner support.
	default:
		return fmt.Errorf("unsupported provisioner type %s", typ)
	}
	if err != nil {
		return err
	}

	if p, err = client.CreateProvisioner(p); err != nil {
		return err
	}

	var buf bytes.Buffer
	b, err := protojson.Marshal(p)
	if err != nil {
		return err
	}
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return err
	}
	fmt.Println(buf.String())

	return nil
}

func createJWKDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	var (
		err      error
		password string
	)
	if passwordFile := ctx.String("password-file"); len(passwordFile) > 0 {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return nil, err
		}
	}

	var (
		jwk *jose.JSONWebKey
		jwe *jose.JSONWebEncryption
	)
	if ctx.Bool("create") {
		if ctx.IsSet("public-key") {
			return nil, errs.IncompatibleFlag(ctx, "create", "public-key")
		}
		if ctx.IsSet("private-key") {
			return nil, errs.IncompatibleFlag(ctx, "create", "private-key")
		}
		pass, err := ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]", ui.WithValue(password))
		if err != nil {
			return nil, err
		}
		jwk, jwe, err = jose.GenerateDefaultKeyPair(pass)
		if err != nil {
			return nil, err
		}
	} else {
		if !ctx.IsSet("public-key") {
			return nil, errs.RequiredWithFlagValue(ctx, "create", "false", "public-key")
		}
		jwkFile := ctx.String("public-key")
		jwk, err = jose.ParseKey(jwkFile)
		if err != nil {
			return nil, errs.FileError(err, jwkFile)
		}

		// Only use asymmetric cryptography
		if _, ok := jwk.Key.([]byte); ok {
			return nil, errors.New("invalid JWK: a symmetric key cannot be used as a provisioner")
		}
		// Create kid if not present
		if jwk.KeyID == "" {
			jwk.KeyID, err = jose.Thumbprint(jwk)
			if err != nil {
				return nil, err
			}
		}

		if ctx.IsSet("private-key") {
			jwkFile = ctx.String("private-key")
			b, err := ioutil.ReadFile(jwkFile)
			if err != nil {
				return nil, errors.Wrapf(err, "error reading %s", jwkFile)
			}

			// Attempt to parse private key as Encrypted JSON.
			// If this operation fails then either,
			//   1. the key is not encrypted
			//   2. the key has an invalid format
			//
			// Attempt to parse as decrypted private key.
			jwe, err = jose.ParseEncrypted(string(b))
			if err != nil {
				privjwk, err := jose.ParseKey(jwkFile)
				if err != nil {
					return nil, errs.FileError(err, jwkFile)
				}

				if privjwk.IsPublic() {
					return nil, errors.New("invalid jwk: private-key is a public key")
				}

				// Encrypt JWK
				opts := []jose.Option{}
				if ctx.IsSet("password-file") {
					opts = append(opts, jose.WithPasswordFile(ctx.String("password-file")))
				}
				jwe, err = jose.EncryptJWK(privjwk, opts...)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	jwkPubBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling JWK")
	}
	jwkProv := &linkedca.JWKProvisioner{
		PublicKey: jwkPubBytes,
	}

	if jwe != nil {
		jwePrivStr, err := jwe.CompactSerialize()
		if err != nil {
			return nil, errors.Wrap(err, "error serializing JWE")
		}
		jwkProv.EncryptedPrivateKey = []byte(jwePrivStr)
	}

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_JWK{
			JWK: jwkProv,
		},
	}, nil
}

func createACMEDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_ACME{
			ACME: &linkedca.ACMEProvisioner{
				ForceCn: ctx.Bool("force-cn"),
			},
		},
	}, nil
}

func createSSHPOPDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_SSHPOP{
			SSHPOP: &linkedca.SSHPOPProvisioner{},
		},
	}, nil
}

func createX5CDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	x5cRootFile := ctx.String("x5c-root")
	if x5cRootFile == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "type", "x5c", "x5c-root")
	}

	roots, err := pemutil.ReadCertificateBundle(x5cRootFile)
	if err != nil {
		return nil, errors.Wrapf(err, "error loading X5C Root certificates from %s", x5cRootFile)
	}
	var rootBytes [][]byte
	for _, r := range roots {
		if r.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.Errorf("error: certificate with common name '%s' cannot be "+
				"used as an X5C root certificate.\n\n"+
				"X5C provisioner root certificates must have the 'Certificate Sign' key "+
				"usage extension.", r.Subject.CommonName)
		}
		rootBytes = append(rootBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: r.Raw,
		}))
	}
	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_X5C{
			X5C: &linkedca.X5CProvisioner{
				Roots: rootBytes,
			},
		},
	}, nil
}

func createK8SSADetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	pemKeysF := ctx.String("public-key")
	if pemKeysF == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "type", "k8sSA", "public-key")
	}

	pemKeysB, err := ioutil.ReadFile(pemKeysF)
	if err != nil {
		return nil, errors.Wrap(err, "error reading pem keys")
	}

	var (
		block   *pem.Block
		rest    = pemKeysB
		pemKeys = []interface{}{}
	)
	for rest != nil {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := pemutil.ParseKey(pem.EncodeToMemory(block))
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing public key from %s", pemKeysF)
		}
		switch q := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		default:
			return nil, errors.Errorf("Unexpected public key type %T in %s", q, pemKeysF)
		}
		pemKeys = append(pemKeys, key)
	}

	var pubKeyBytes [][]byte
	for _, k := range pemKeys {
		blk, err := pemutil.Serialize(k)
		if err != nil {
			return nil, errors.Wrap(err, "error serializing pem key")
		}
		pubKeyBytes = append(pubKeyBytes, pem.EncodeToMemory(blk))
	}
	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_K8SSA{
			K8SSA: &linkedca.K8SSAProvisioner{
				PublicKeys: pubKeyBytes,
			},
		},
	}, nil
}

func createOIDCDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	clientID := ctx.String("client-id")
	if clientID == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "type", ctx.String("type"), "client-id")
	}

	confURL := ctx.String("configuration-endpoint")
	if confURL == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "type", ctx.String("type"), "configuration-endpoint")
	}
	u, err := url.Parse(confURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errs.InvalidFlagValue(ctx, "configuration-endpoint", confURL, "")
	}

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_OIDC{
			OIDC: &linkedca.OIDCProvisioner{
				ClientId:              clientID,
				ClientSecret:          ctx.String("client-secret"),
				ConfigurationEndpoint: confURL,
				Admins:                ctx.StringSlice("admin"),
				Domains:               ctx.StringSlice("domain"),
				Groups:                ctx.StringSlice("group"),
				ListenAddress:         ctx.String("listen-address"),
				TenantId:              ctx.String("tenant-id"),
			},
		},
	}, nil
}

func createAWSDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	d, err := parseIntaceAge(ctx)
	if err != nil {
		return nil, err
	}

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_AWS{
			AWS: &linkedca.AWSProvisioner{
				Accounts:               ctx.StringSlice("aws-account"),
				DisableCustomSans:      ctx.Bool("disable-custom-sans"),
				DisableTrustOnFirstUse: ctx.Bool("disable-trust-on-first-use"),
				InstanceAge:            d,
				// TODO IID Roots
				// IIDRoots:               ctx.String("iid-roots"),
			},
		},
	}, nil
}

func createAzureDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	tenantID := ctx.String("azure-tenant")
	if tenantID == "" {
		return nil, errs.RequiredWithFlagValue(ctx, "type", ctx.String("type"), "azure-tenant")
	}

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_Azure{
			Azure: &linkedca.AzureProvisioner{
				TenantId:               tenantID,
				ResourceGroups:         ctx.StringSlice("azure-resource-group"),
				DisableCustomSans:      ctx.Bool("disable-custom-sans"),
				DisableTrustOnFirstUse: ctx.Bool("disable-trust-on-first-use"),
			},
		},
	}, nil
}

func createGCPDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	d, err := parseIntaceAge(ctx)
	if err != nil {
		return nil, err
	}

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_GCP{
			GCP: &linkedca.GCPProvisioner{
				ServiceAccounts:        ctx.StringSlice("gcp-service-account"),
				ProjectIds:             ctx.StringSlice("gcp-project"),
				DisableCustomSans:      ctx.Bool("disable-custom-sans"),
				DisableTrustOnFirstUse: ctx.Bool("disable-trust-on-first-use"),
				InstanceAge:            d,
			},
		},
	}, nil
}
