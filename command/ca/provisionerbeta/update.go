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
	"github.com/smallstep/certificates/ca"
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

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update a provisioner",
		UsageText: `**step beta ca provisioner update** <name> [**--public-key**=<file>]
[**--private-key**=<file>] [**--create**] [**--password-file**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

ACME

**step beta ca provisioner update** <name> [**--force-cn**]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

OIDC

**step beta ca provisioner update** <name>
[**--client-id**=<id>] [**--client-secret**=<secret>]
[**--configuration-endpoint**=<url>] [**--listen-address=<address>]
[**--domain**=<domain>] [**--remove-domain**=<domain>]
[**--group**=<group>] [**--remove-group**=<group>]
[**--admin**=<email>]... [**--remove-admin**=<email>]...
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

X5C

**step beta ca provisioner update** <name> **--x5c-root**=<file>
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

Kubernetes Service Account

**step beta ca provisioner update** <name> [**--public-key**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]

IID (AWS/GCP/Azure)

**step beta ca provisioner update** <name>
[**--aws-account**=<id>]... [**--remove-aws-account**=<id>]...
[**--gcp-service-account**=<name>]... [**--remove-gcp-service-account**=<name>]...
[**--gcp-project**=<name>]... [**--remove-gcp-project**=<name>]...
[**--azure-tenant**=<id>] [**--azure-resource-group**=<name>]
[**--instance-age**=<duration>] [**--iid-roots**=<file>]
[**--disable-custom-sans**] [**--disable-trust-on-first-use**]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "name",
				Usage: `The new <name> for the provisioner.`,
			},
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
				Name:  "public-key",
				Usage: `The <file> containing the JWK public key.`,
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
				Name: "remove-admin",
				Usage: `Remove the <email> of an admin user in an OpenID Connect provisioner, this user
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
			removeAWSAccountFlag,
			azureTenantFlag,
			azureResourceGroupFlag,
			removeAzureResourceGroupFlag,
			gcpServiceAccountFlag,
			removeGCPServiceAccountFlag,
			gcpProjectFlag,
			removeGCPProjectFlag,
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
		Description: `**step ca provisioner update** updates a provisioner in the CA configuration.

## POSITIONAL ARGUMENTS

<name>
: The name of the provisioner.

## EXAMPLES

Update a JWK provisioner with newly generated keys and a template for x509 certificates:
'''
step beta ca provisioner update cicd --create --x509-template ./templates/example.tpl
'''

Update a JWK provisioner with duration claims:
'''
step beta ca provisioner update cicd --create --x509-min-dur 20m --x509-default-dur 48h --ssh-user-min-dur 17m --ssh-host-default-dur 16h
'''

Update a JWK provisioner with existing keys:
'''
step beta ca provisioner update jane@doe.com --public-key jwk.pub --private-key jwk.priv
'''

Update a JWK provisioner to disable ssh provisioning:
'''
step beta ca provisioner update cicd --ssh=false
'''

Update an OIDC provisioner:
'''
step beta ca provisioner update Google \
	--configuration-endpoint https://accounts.google.com/.well-known/openid-configuration
'''

Update an X5C provisioner:
'''
step beta ca provisioner update x5c --x5c-root x5c_ca.crt
'''

Update an ACME provisioner:
'''
step beta ca provisioner update acme --force-cn
'''

Update an K8SSA provisioner:
'''
step beta ca provisioner update kube --public-key key.pub --x509-min-duration 30m
'''

Update an Azure provisioner:
'''
$ step beta ca provisioner update Azure \
  --azure-resource-group identity --azure-resource-group accounting
'''

Update an GCP provisioner:
'''
$ step beta ca provisioner update Google \
  --disable-custom-sans --gcp-project internal --remove-gcp-project public
'''

Update an AWS provisioner:
'''
$ step beta ca provisioner update Amazon --disable-custom-sans --disable-trust-on-first-use
'''`,
	}
}

func updateAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args[0]

	// Create online client
	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	p, err := client.GetProvisioner(ca.WithProvisionerName(name))
	if err != nil {
		return err
	}

	if ctx.IsSet("name") {
		p.Name = ctx.String("name")
	}
	if err := updateTemplates(ctx, p); err != nil {
		return err
	}
	updateClaims(ctx, p)

	switch p.Type {
	case linkedca.Provisioner_JWK:
		err = updateJWKDetails(ctx, p)
	case linkedca.Provisioner_ACME:
		err = updateACMEDetails(ctx, p)
	case linkedca.Provisioner_SSHPOP:
		err = updateSSHPOPDetails(ctx, p)
	case linkedca.Provisioner_X5C:
		err = updateX5CDetails(ctx, p)
	case linkedca.Provisioner_K8SSA:
		err = updateK8SSADetails(ctx, p)
	case linkedca.Provisioner_OIDC:
		err = updateOIDCDetails(ctx, p)
	case linkedca.Provisioner_AWS:
		err = updateAWSDetails(ctx, p)
	case linkedca.Provisioner_AZURE:
		err = updateAzureDetails(ctx, p)
	case linkedca.Provisioner_GCP:
		err = updateGCPDetails(ctx, p)
	// TODO add SCEP provisioner support.
	default:
		return fmt.Errorf("unsupported provisioner type %s", p.Type.String())
	}
	if err != nil {
		return err
	}

	if err := client.UpdateProvisioner(name, p); err != nil {
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

func updateTemplates(ctx *cli.Context, p *linkedca.Provisioner) error {
	// Read x509 template if passed
	if p.X509Template == nil {
		p.X509Template = &linkedca.Template{}
	}
	if x509TemplateFile := ctx.String("x509-template"); ctx.IsSet("x509-template") {
		if x509TemplateFile == "" {
			p.X509Template.Template = nil
		} else {
			b, err := utils.ReadFile(x509TemplateFile)
			if err != nil {
				return err
			}
			p.X509Template.Template = b
		}
	}
	if x509TemplateDataFile := ctx.String("x509-template-data"); ctx.IsSet("x509-template-data") {
		if x509TemplateDataFile == "" {
			p.X509Template.Data = nil
		} else {
			b, err := utils.ReadFile(x509TemplateDataFile)
			if err != nil {
				return err
			}
			p.X509Template.Data = b
		}
	}
	// Read ssh template if passed
	if p.SshTemplate == nil {
		p.SshTemplate = &linkedca.Template{}
	}
	if sshTemplateFile := ctx.String("ssh-template"); ctx.IsSet("ssh-template") {
		if sshTemplateFile == "" {
			p.SshTemplate.Template = nil
		} else {
			b, err := utils.ReadFile(sshTemplateFile)
			if err != nil {
				return err
			}
			p.SshTemplate.Template = b
		}
	}
	if sshTemplateDataFile := ctx.String("ssh-template-data"); ctx.IsSet("ssh-template-data") {
		if sshTemplateDataFile == "" {
			p.SshTemplate.Data = nil
		} else {
			b, err := utils.ReadFile(sshTemplateDataFile)
			if err != nil {
				return err
			}
			p.SshTemplate.Data = b
		}
	}
	return nil
}

func updateClaims(ctx *cli.Context, p *linkedca.Provisioner) {
	if p.Claims == nil {
		p.Claims = &linkedca.Claims{}
	}
	if ctx.IsSet("disable-renewal") {
		p.Claims.DisableRenewal = ctx.Bool("disable-renewal")
	}
	claims := p.Claims

	if claims.X509 == nil {
		claims.X509 = &linkedca.X509Claims{}
	}
	xc := claims.X509
	if ctx.IsSet("x509") {
		claims.X509.Enabled = ctx.Bool("x509")
	}
	if xc.Durations == nil {
		xc.Durations = &linkedca.Durations{}
	}
	d := claims.X509.Durations
	if ctx.IsSet("x509-min-dur") {
		d.Min = ctx.String("x509-min-dur")
	}
	if ctx.IsSet("x509-max-dur") {
		d.Max = ctx.String("x509-max-dur")
	}
	if ctx.IsSet("x509-default-dur") {
		d.Default = ctx.String("x509-default-dur")
	}

	if claims.Ssh == nil {
		claims.Ssh = &linkedca.SSHClaims{}
	}
	sc := claims.Ssh
	if ctx.IsSet("ssh") {
		sc.Enabled = ctx.Bool("ssh")
	}
	if sc.UserDurations == nil {
		sc.UserDurations = &linkedca.Durations{}
	}
	d = sc.UserDurations
	if ctx.IsSet("ssh-user-min-dur") {
		d.Min = ctx.String("ssh-user-min-dur")
	}
	if ctx.IsSet("ssh-user-max-dur") {
		d.Max = ctx.String("ssh-user-max-dur")
	}
	if ctx.IsSet("ssh-user-default-dur") {
		d.Default = ctx.String("ssh-user-default-dur")
	}
	if sc.HostDurations == nil {
		sc.HostDurations = &linkedca.Durations{}
	}
	d = sc.HostDurations
	if ctx.IsSet("ssh-host-min-dur") {
		d.Min = ctx.String("ssh-host-min-dur")
	}
	if ctx.IsSet("ssh-host-max-dur") {
		d.Max = ctx.String("ssh-host-max-dur")
	}
	if ctx.IsSet("ssh-host-default-dur") {
		d.Default = ctx.String("ssh-host-default-dur")
	}
}

func updateJWKDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_JWK)
	if !ok {
		return errors.New("error casting details to ACME type")
	}
	details := data.JWK

	var (
		err      error
		password string
	)
	if passwordFile := ctx.String("password-file"); len(passwordFile) > 0 {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	var (
		jwk *jose.JSONWebKey
		jwe *jose.JSONWebEncryption
	)
	if ctx.Bool("create") {
		if ctx.IsSet("public-key") {
			return errs.IncompatibleFlag(ctx, "create", "public-key")
		}
		if ctx.IsSet("private-key") {
			return errs.IncompatibleFlag(ctx, "create", "private-key")
		}
		pass, err := ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]", ui.WithValue(password))
		if err != nil {
			return err
		}
		jwk, jwe, err = jose.GenerateDefaultKeyPair(pass)
		if err != nil {
			return err
		}
	} else {
		if ctx.IsSet("public-key") {
			jwkFile := ctx.String("public-key")
			jwk, err = jose.ParseKey(jwkFile)
			if err != nil {
				return errs.FileError(err, jwkFile)
			}

			// Only use asymmetric cryptography
			if _, ok := jwk.Key.([]byte); ok {
				return errors.New("invalid JWK: a symmetric key cannot be used as a provisioner")
			}
			// Create kid if not present
			if jwk.KeyID == "" {
				jwk.KeyID, err = jose.Thumbprint(jwk)
				if err != nil {
					return err
				}
			}
		}

		if ctx.IsSet("private-key") {
			jwkFile := ctx.String("private-key")
			b, err := ioutil.ReadFile(jwkFile)
			if err != nil {
				return errors.Wrapf(err, "error reading %s", jwkFile)
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
					return errs.FileError(err, jwkFile)
				}

				if privjwk.IsPublic() {
					return errors.New("invalid jwk: private-key is a public key")
				}

				// Encrypt JWK
				opts := []jose.Option{}
				if ctx.IsSet("password-file") {
					opts = append(opts, jose.WithPasswordFile(ctx.String("password-file")))
				}
				jwe, err = jose.EncryptJWK(privjwk, opts...)
				if err != nil {
					return err
				}
			}
		}
	}

	if jwk != nil {
		jwkPubBytes, err := jwk.MarshalJSON()
		if err != nil {
			return errors.Wrap(err, "error marshaling JWK")
		}
		details.PublicKey = jwkPubBytes
	}

	if jwe != nil {
		jwePrivStr, err := jwe.CompactSerialize()
		if err != nil {
			return errors.Wrap(err, "error serializing JWE")
		}
		details.EncryptedPrivateKey = []byte(jwePrivStr)
	}

	return nil
}

func updateACMEDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_ACME)
	if !ok {
		return errors.New("error casting details to ACME type")
	}
	details := data.ACME
	if ctx.IsSet("force-cn") {
		details.ForceCn = ctx.Bool("force-cn")
	}
	return nil
}

func updateSSHPOPDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	return nil
}

func updateX5CDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_X5C)
	if !ok {
		return errors.New("error casting details to X5C type")
	}
	details := data.X5C
	if ctx.IsSet("x5c-root") {
		x5cRootFile := ctx.String("x5c-root")
		roots, err := pemutil.ReadCertificateBundle(x5cRootFile)
		if err != nil {
			return errors.Wrapf(err, "error loading X5C Root certificates from %s", x5cRootFile)
		}
		var rootBytes [][]byte
		for _, r := range roots {
			if r.KeyUsage&x509.KeyUsageCertSign == 0 {
				return errors.Errorf("error: certificate with common name '%s' cannot be "+
					"used as an X5C root certificate.\n\n"+
					"X5C provisioner root certificates must have the 'Certificate Sign' key "+
					"usage extension.", r.Subject.CommonName)
			}
			rootBytes = append(rootBytes, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: r.Raw,
			}))
		}
		details.Roots = rootBytes
	}
	return nil
}

func updateK8SSADetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_K8SSA)
	if !ok {
		return errors.New("error casting details to K8SSA type")
	}
	details := data.K8SSA
	if ctx.IsSet("public-key") {
		pemKeysF := ctx.String("public-key")
		pemKeysB, err := ioutil.ReadFile(pemKeysF)
		if err != nil {
			return errors.Wrap(err, "error reading pem keys")
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
				return errors.Wrapf(err, "error parsing public key from %s", pemKeysF)
			}
			switch q := key.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			default:
				return errors.Errorf("Unexpected public key type %T in %s", q, pemKeysF)
			}
			pemKeys = append(pemKeys, key)
		}

		var pubKeyBytes [][]byte
		for _, k := range pemKeys {
			blk, err := pemutil.Serialize(k)
			if err != nil {
				return errors.Wrap(err, "error serializing pem key")
			}
			pubKeyBytes = append(pubKeyBytes, pem.EncodeToMemory(blk))
		}
		details.PublicKeys = pubKeyBytes
	}
	return nil
}

func updateOIDCDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_OIDC)
	if !ok {
		return errors.New("error casting details to OIDC type")
	}
	details := data.OIDC
	if ctx.IsSet("client-id") {
		details.ClientId = ctx.String("client-id")
	}
	if ctx.IsSet("client-secret") {
		details.ClientSecret = ctx.String("client-secret")
	}
	if ctx.IsSet("remove-admin") {
		details.Admins = removeElements(details.Admins, ctx.StringSlice("remove-admin"))
	}
	if ctx.IsSet("admin") {
		details.Admins = append(details.Admins, ctx.StringSlice("admin")...)
	}
	if ctx.IsSet("remove-domain") {
		details.Domains = removeElements(details.Domains, ctx.StringSlice("remove-domain"))
	}
	if ctx.IsSet("domain") {
		details.Domains = append(details.Domains, ctx.StringSlice("domain")...)
	}
	if ctx.IsSet("remove-group") {
		details.Groups = removeElements(details.Groups, ctx.StringSlice("remove-group"))
	}
	if ctx.IsSet("group") {
		details.Groups = append(details.Groups, ctx.StringSlice("group")...)
	}
	if ctx.IsSet("listen-address") {
		details.ListenAddress = ctx.String("listen-address")
	}
	if ctx.IsSet("tenant-id") {
		details.TenantId = ctx.String("tenant-id")
	}
	if ctx.IsSet("configuration-endpoint") {
		ce := ctx.String("configuration-endpoint")
		u, err := url.Parse(ce)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return errs.InvalidFlagValue(ctx, "configuration-endpoint", ce, "")
		}
		details.ConfigurationEndpoint = ce
	}
	return nil
}

func updateAWSDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_AWS)
	if !ok {
		return errors.New("error casting details to OIDC type")
	}
	details := data.AWS

	var err error
	if ctx.IsSet("instance-age") {
		details.InstanceAge, err = parseIntaceAge(ctx)
		if err != nil {
			return err
		}
	}
	if ctx.IsSet("disable-custom-sans") {
		details.DisableCustomSans = ctx.Bool("disable-custom-sans")
	}
	if ctx.IsSet("disable-trust-on-first-use") {
		details.DisableCustomSans = ctx.Bool("disable-trust-on-first-use")
	}
	if ctx.IsSet("remove-aws-account") {
		details.Accounts = removeElements(details.Accounts, ctx.StringSlice("remove-aws-account"))
	}
	if ctx.IsSet("aws-account") {
		details.Accounts = append(details.Accounts, ctx.StringSlice("add-aws-account")...)
	}
	return nil
}

func updateAzureDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_Azure)
	if !ok {
		return errors.New("error casting details to OIDC type")
	}
	details := data.Azure

	if ctx.IsSet("azure-tenant") {
		details.TenantId = ctx.String("azure-tenant")
	}
	if ctx.IsSet("disable-custom-sans") {
		details.DisableCustomSans = ctx.Bool("disable-custom-sans")
	}
	if ctx.IsSet("disable-trust-on-first-use") {
		details.DisableCustomSans = ctx.Bool("disable-trust-on-first-use")
	}
	if ctx.IsSet("remove-azure-resource-group") {
		details.ResourceGroups = removeElements(details.ResourceGroups, ctx.StringSlice("remove-azure-resource-group"))
	}
	if ctx.IsSet("azure-resource-group") {
		details.ResourceGroups = append(details.ResourceGroups, ctx.StringSlice("add-azure-resource-group")...)
	}
	return nil
}

func updateGCPDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_GCP)
	if !ok {
		return errors.New("error casting details to OIDC type")
	}
	details := data.GCP

	var err error
	if ctx.IsSet("instance-age") {
		details.InstanceAge, err = parseIntaceAge(ctx)
		if err != nil {
			return err
		}
	}
	if ctx.IsSet("disable-custom-sans") {
		details.DisableCustomSans = ctx.Bool("disable-custom-sans")
	}
	if ctx.IsSet("disable-trust-on-first-use") {
		details.DisableCustomSans = ctx.Bool("disable-trust-on-first-use")
	}
	if ctx.IsSet("remove-gcp-service-account") {
		details.ServiceAccounts = removeElements(details.ServiceAccounts, ctx.StringSlice("remove-gcp-service-account"))
	}
	if ctx.IsSet("gcp-service-account") {
		details.ServiceAccounts = append(details.ServiceAccounts, ctx.StringSlice("add-gcp-service-account")...)
	}
	if ctx.IsSet("remove-gcp-project") {
		details.ProjectIds = removeElements(details.ProjectIds, ctx.StringSlice("gcp-project"))
	}
	if ctx.IsSet("gcp-project") {
		details.ProjectIds = append(details.ProjectIds, ctx.StringSlice("add-gcp-project")...)
	}
	return nil
}
