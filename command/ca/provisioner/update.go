package provisioner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/linkedca"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sliceutil"
	"github.com/smallstep/cli/utils"
)

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update a provisioner",
		UsageText: `**step ca provisioner update** <name> [**--public-key**=<file>]
[**--private-key**=<file>] [**--create**] [**--password-file**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>] [**--ssh-template**=<file>]
[**--ssh-template-data**=<file>]

ACME

**step ca provisioner update** <name> [**--force-cn**] [**--require-eab**]
[**--challenge**=<challenge>] [**--remove-challenge**=<challenge>]
[**--attestation-format**=<format>] [**--remove-attestation-format**=<format>]
[**--attestation-roots**=<file>] [**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-subject**=<subject>] [**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>]

OIDC

**step ca provisioner update** <name>
[**--client-id**=<id>] [**--client-secret**=<secret>]
[**--configuration-endpoint**=<url>] [**--listen-address=<address>]
[**--domain**=<domain>] [**--remove-domain**=<domain>]
[**--group**=<group>] [**--remove-group**=<group>]
[**--admin**=<email>]... [**--remove-admin**=<email>]...
[**--scope**=<scope>] [**--remove-scope**=<scope>]
[**--auth-param**=<auth-param>] [**--remove-auth-param**=<auth-param>]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-subject**=<subject>] [**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>] [**--ssh-template**=<file>]
[**--ssh-template-data**=<file>]

X5C

**step ca provisioner update** <name> **--x5c-roots**=<file>
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-subject**=<subject>] [**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>] [**--ssh-template**=<file>]
[**--ssh-template-data**=<file>]

K8SSA (Kubernetes Service Account)

**step ca provisioner update** <name> [**--public-key**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-subject**=<subject>] [**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>]

IID (AWS/GCP/Azure)

**step ca provisioner update** <name>
[**--aws-account**=<id>]... [**--remove-aws-account**=<id>]...
[**--gcp-service-account**=<name>]... [**--remove-gcp-service-account**=<name>]...
[**--gcp-project**=<name>]... [**--remove-gcp-project**=<name>]...
[**--azure-tenant**=<id>] [**--azure-resource-group**=<name>]
[**--azure-audience**=<name>] [**--azure-subscription-id**=<id>]
[**--azure-object-id**=<id>] [**--instance-age**=<duration>]
[**--disable-custom-sans**] [**--disable-trust-on-first-use**]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-subject**=<subject>] [**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>] [**--ssh-template**=<file>]
[**--ssh-template-data**=<file>]

SCEP

**step ca provisioner update** <name> [**--force-cn**] [**--challenge**=<challenge>]
[**--capabilities**=<capabilities>] [**--include-root**] [**--exclude-intermediate**]
[**--minimum-public-key-length**=<length>] [**--encryption-algorithm-identifier**=<id>]
[**--scep-decrypter-certificate-file**=<file>] [**--scep-decrypter-key-file**=<file>]
[**--scep-decrypter-key-uri**=<uri>] [**--scep-decrypter-key-password-file**=<file>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]
[**--x509-template**=<file>] [**--x509-template-data**=<file>]`,
		Flags: []cli.Flag{
			nameFlag,
			pubKeyFlag,

			// JWK provisioner flags
			jwkCreateFlag,
			jwkPrivKeyFlag,

			// OIDC provisioner flags
			oidcClientIDFlag,
			oidcClientSecretFlag,
			oidcListenAddressFlag,
			oidcConfigEndpointFlag,
			oidcAdminFlag,
			oidcRemoveAdminFlag,
			oidcDomainFlag,
			oidcRemoveDomainFlag,
			oidcGroupFlag,
			oidcTenantIDFlag,
			oidcScopeFlag,
			oidcRemoveScopeFlag,
			oidcAuthParamFlag,

			// X5C Root Flag
			x5cRootsFlag,

			// Nebula provisioner flags
			nebulaRootFlag,

			// ACME provisioner flags
			requireEABFlag,              // ACME
			forceCNFlag,                 // ACME + SCEP
			challengeFlag,               // ACME + SCEP
			removeChallengeFlag,         // ACME
			attestationFormatFlag,       // ACME
			removeAttestationFormatFlag, // ACME
			attestationRootsFlag,        // ACME

			// SCEP flags
			scepCapabilitiesFlag,
			scepIncludeRootFlag,
			scepExcludeIntermediateFlag,
			scepMinimumPublicKeyLengthFlag,
			scepEncryptionAlgorithmIdentifierFlag,
			scepDecrypterCertFileFlag,
			scepDecrypterKeyFileFlag,
			scepDecrypterKeyURIFlag,
			scepDecrypterKeyPasswordFileFlag,

			// Cloud provisioner flags
			awsAccountFlag,
			removeAWSAccountFlag,
			azureTenantFlag,
			azureResourceGroupFlag,
			removeAzureResourceGroupFlag,
			azureAudienceFlag,
			azureSubscriptionIDFlag,
			removeAzureSubscriptionIDFlag,
			azureObjectIDFlag,
			removeAzureObjectIDFlag,
			gcpServiceAccountFlag,
			removeGCPServiceAccountFlag,
			gcpProjectFlag,
			removeGCPProjectFlag,
			instanceAgeFlag,
			disableCustomSANsFlag,
			disableTOFUFlag,

			// Claims
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
			allowRenewalAfterExpiryFlag,
			disableSmallstepExtensionsFlag,
			//enableX509Flag,
			enableSSHFlag,

			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFileNoAlias,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
			flags.CaConfig,
		},
		Description: `**step ca provisioner update** updates a provisioner in the CA configuration.

## POSITIONAL ARGUMENTS

<name>
: The name of the provisioner.

## EXAMPLES

Update a JWK provisioner with newly generated keys and a template for x509 certificates:
'''
step ca provisioner update cicd --create --x509-template ./templates/example.tpl
'''

Update a JWK provisioner by removing a previously set template:
'''
step ca provisioner update cicd --x509-template ""
'''

Update a JWK provisioner with duration claims:
'''
step ca provisioner update cicd --x509-min-dur 20m --x509-default-dur 48h --ssh-user-min-dur 17m --ssh-host-default-dur 16h
'''

Update a JWK provisioner with existing keys:
'''
step ca provisioner update jane@doe.com --public-key jwk.pub --private-key jwk.priv
'''

Update a JWK provisioner to disable ssh provisioning:
'''
step ca provisioner update cicd --ssh=false
'''

Update a JWK provisioner by removing a previously cached private key:
'''
step ca provisioner update cicd --private-key=""
'''

Update a JWK provisioner and explicitly select the ca.json to modify:
'''
step ca provisioner update cicd --ssh=false --ca-config /path/to/ca.json
'''

Update an OIDC provisioner:
'''
step ca provisioner update Google \
	--configuration-endpoint https://accounts.google.com/.well-known/openid-configuration
'''

Update an X5C provisioner:
'''
step ca provisioner update x5c --x5c-roots x5c_ca.crt
'''

Update an ACME provisioner:
'''
step ca provisioner update acme --force-cn --require-eab
'''

Update an K8SSA provisioner:
'''
step ca provisioner update kube --public-key key.pub --x509-min-duration 30m
'''

Update an Azure provisioner:
'''
$ step ca provisioner update Azure \
  --azure-resource-group identity --azure-resource-group accounting
'''

Update a GCP provisioner:
'''
$ step ca provisioner update Google \
  --disable-custom-sans --gcp-project internal --remove-gcp-project public
'''

Update an AWS provisioner:
'''
$ step ca provisioner update Amazon --disable-custom-sans --disable-trust-on-first-use
'''

Update a SCEP provisioner:
'''
step ca provisioner update my_scep_provisioner --force-cn
'''`,
	}
}

func updateAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args[0]

	client, err := newCRUDClient(ctx, ctx.String("ca-config"))
	if err != nil {
		return err
	}

	p, err := client.GetProvisioner(ca.WithProvisionerName(name))
	if err != nil {
		return err
	}

	// Validate challenge flag on scep and acme
	if err := validateChallengeFlag(ctx, p.Type); err != nil {
		return err
	}

	// Validate attestation format flag on acme
	if err := validateAttestationFormatFlag(ctx, p.Type); err != nil {
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
	case linkedca.Provisioner_SCEP:
		err = updateSCEPDetails(ctx, p)
	case linkedca.Provisioner_NEBULA:
		err = updateNebulaDetails(ctx, p)
	default:
		return fmt.Errorf("unsupported provisioner type %s", p.Type.String())
	}
	if err != nil {
		return err
	}

	return client.UpdateProvisioner(name, p)
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
	if ctx.IsSet("allow-renewal-after-expiry") {
		p.Claims.AllowRenewalAfterExpiry = ctx.Bool("allow-renewal-after-expiry")
	}
	if ctx.IsSet("disable-smallstep-extensions") {
		p.Claims.DisableSmallstepExtensions = ctx.Bool("disable-smallstep-extensions")
	}

	claims := p.Claims
	if claims.X509 == nil {
		claims.X509 = &linkedca.X509Claims{}
	}
	xc := claims.X509
	// TODO for the time being x509 is always enabled.
	//if ctx.IsSet("x509") {
	//	claims.X509.Enabled = ctx.Bool("x509")
	//}
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
		return errors.New("error casting details to JWK type")
	}
	details := data.JWK

	var (
		err      error
		password string
	)
	if passwordFile := ctx.String("password-file"); passwordFile != "" {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	var (
		jwk              *jose.JSONWebKey
		jwe              *jose.JSONWebEncryption
		removePrivateKey bool
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
			jwk, err = jose.ReadKey(jwkFile)
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

		if ctx.IsSet("private-key") && ctx.String("private-key") == "" {
			removePrivateKey = true
		} else if ctx.IsSet("private-key") {
			jwkFile := ctx.String("private-key")
			b, err := os.ReadFile(jwkFile)
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
				privjwk, err := jose.ParseKey(b)
				if err != nil {
					return errs.FileError(err, jwkFile)
				}

				if privjwk.IsPublic() {
					return errors.New("invalid jwk: private-key is a public key")
				}

				// Encrypt JWK
				var passbytes []byte
				if ctx.IsSet("password-file") {
					passbytes, err = os.ReadFile(ctx.String("password-file"))
					if err != nil {
						return errs.FileError(err, ctx.String("password-file"))
					}
				} else {
					passbytes, err = ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]",
						ui.WithValue(password))
					if err != nil {
						return err
					}
				}
				jwe, err = jose.EncryptJWK(privjwk, passbytes)
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

	if removePrivateKey {
		details.EncryptedPrivateKey = nil
	} else if jwe != nil {
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
	if ctx.IsSet("require-eab") {
		details.RequireEab = ctx.Bool("require-eab")
	}
	if ctx.IsSet("remove-challenge") {
		values := acmeChallengeToLinkedca(ctx.StringSlice("remove-challenge"))
		details.Challenges = sliceutil.RemoveValues(details.Challenges, values)
	}
	if ctx.IsSet("challenge") {
		values := acmeChallengeToLinkedca(ctx.StringSlice("challenge"))
		details.Challenges = append(details.Challenges, values...)
	}
	if ctx.IsSet("challenge") || ctx.IsSet("remove-challenge") {
		details.Challenges = sliceutil.RemoveDuplicates(details.Challenges)
	}
	if ctx.IsSet("remove-attestation-format") {
		values := acmeAttestationFormatToLinkedca(ctx.StringSlice("remove-attestation-format"))
		details.AttestationFormats = sliceutil.RemoveValues(details.AttestationFormats, values)
	}
	if ctx.IsSet("attestation-format") {
		values := acmeAttestationFormatToLinkedca(ctx.StringSlice("attestation-format"))
		details.AttestationFormats = append(details.AttestationFormats, values...)
	}
	if ctx.IsSet("attestation-format") || ctx.IsSet("remove-attestation-format") {
		details.AttestationFormats = sliceutil.RemoveDuplicates(details.AttestationFormats)
	}
	if ctx.IsSet("attestation-roots") {
		attestationRoots, err := parseCACertificates(ctx.StringSlice("attestation-roots"))
		if err != nil {
			return err
		}
		details.AttestationRoots = attestationRoots
	}
	return nil
}

func updateSSHPOPDetails(*cli.Context, *linkedca.Provisioner) error {
	return nil
}

func updateX5CDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_X5C)
	if !ok {
		return errors.New("error casting details to X5C type")
	}
	details := data.X5C
	if ctx.IsSet("x5c-roots") {
		x5cRootFile := ctx.String("x5c-roots")
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

func updateNebulaDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_Nebula)
	if !ok {
		return errors.New("error casting details to Nebula type")
	}

	details := data.Nebula
	if ctx.IsSet("nebula-root") {
		rootBytes, err := readNebulaRoots(ctx.String("nebula-root"))
		if err != nil {
			return err
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
		pemKeysB, err := os.ReadFile(pemKeysF)
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
	if ctx.IsSet("remove-scope") {
		details.Scopes = removeElements(details.Scopes, ctx.StringSlice("remove-scope"))
	}
	if ctx.IsSet("scope") {
		details.Scopes = append(details.Scopes, ctx.StringSlice("scope")...)
	}
	if ctx.IsSet("remove-auth-param") {
		details.AuthParams = removeElements(details.AuthParams, ctx.StringSlice("remove-auth-param"))
	}
	if ctx.IsSet("auth-param") {
		details.AuthParams = append(details.AuthParams, ctx.StringSlice("auth-param")...)
	}
	return nil
}

func updateAWSDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_AWS)
	if !ok {
		return errors.New("error casting details to AWS type")
	}
	details := data.AWS

	var err error
	if ctx.IsSet("instance-age") {
		details.InstanceAge, err = parseInstanceAge(ctx)
		if err != nil {
			return err
		}
	}
	if ctx.IsSet("disable-custom-sans") {
		details.DisableCustomSans = ctx.Bool("disable-custom-sans")
	}
	if ctx.IsSet("disable-trust-on-first-use") {
		details.DisableTrustOnFirstUse = ctx.Bool("disable-trust-on-first-use")
	}
	if ctx.IsSet("remove-aws-account") {
		details.Accounts = removeElements(details.Accounts, ctx.StringSlice("remove-aws-account"))
	}
	if ctx.IsSet("aws-account") {
		details.Accounts = append(details.Accounts, ctx.StringSlice("aws-account")...)
	}
	return nil
}

func updateAzureDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_Azure)
	if !ok {
		return errors.New("error casting details to Azure type")
	}
	details := data.Azure

	if ctx.IsSet("azure-tenant") {
		details.TenantId = ctx.String("azure-tenant")
	}
	if ctx.IsSet("azure-audience") {
		details.Audience = ctx.String("azure-audience")
	}
	if ctx.IsSet("disable-custom-sans") {
		details.DisableCustomSans = ctx.Bool("disable-custom-sans")
	}
	if ctx.IsSet("disable-trust-on-first-use") {
		details.DisableTrustOnFirstUse = ctx.Bool("disable-trust-on-first-use")
	}
	if ctx.IsSet("remove-azure-resource-group") {
		details.ResourceGroups = removeElements(details.ResourceGroups, ctx.StringSlice("remove-azure-resource-group"))
	}
	if ctx.IsSet("azure-resource-group") {
		details.ResourceGroups = append(details.ResourceGroups, ctx.StringSlice("azure-resource-group")...)
	}
	if ctx.IsSet("remove-azure-subscription-id") {
		details.SubscriptionIds = removeElements(details.SubscriptionIds, ctx.StringSlice("remove-azure-subscription-id"))
	}
	if ctx.IsSet("azure-subscription-id") {
		details.SubscriptionIds = append(details.SubscriptionIds, ctx.StringSlice("azure-subscription-id")...)
	}
	if ctx.IsSet("remove-azure-object-id") {
		details.ObjectIds = removeElements(details.ObjectIds, ctx.StringSlice("remove-azure-object-id"))
	}
	if ctx.IsSet("azure-object-id") {
		details.ObjectIds = append(details.ObjectIds, ctx.StringSlice("azure-object-id")...)
	}
	return nil
}

func updateGCPDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_GCP)
	if !ok {
		return errors.New("error casting details to GCP type")
	}
	details := data.GCP

	var err error
	if ctx.IsSet("instance-age") {
		details.InstanceAge, err = parseInstanceAge(ctx)
		if err != nil {
			return err
		}
	}
	if ctx.IsSet("disable-custom-sans") {
		details.DisableCustomSans = ctx.Bool("disable-custom-sans")
	}
	if ctx.IsSet("disable-trust-on-first-use") {
		details.DisableTrustOnFirstUse = ctx.Bool("disable-trust-on-first-use")
	}
	if ctx.IsSet("remove-gcp-service-account") {
		details.ServiceAccounts = removeElements(details.ServiceAccounts, ctx.StringSlice("remove-gcp-service-account"))
	}
	if ctx.IsSet("gcp-service-account") {
		details.ServiceAccounts = append(details.ServiceAccounts, ctx.StringSlice("gcp-service-account")...)
	}
	if ctx.IsSet("remove-gcp-project") {
		details.ProjectIds = removeElements(details.ProjectIds, ctx.StringSlice("remove-gcp-project"))
	}
	if ctx.IsSet("gcp-project") {
		details.ProjectIds = append(details.ProjectIds, ctx.StringSlice("gcp-project")...)
	}
	return nil
}

func updateSCEPDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_SCEP)
	if !ok {
		return errors.New("error casting details to SCEP type")
	}
	details := data.SCEP

	if ctx.IsSet("force-cn") {
		details.ForceCn = ctx.Bool("force-cn")
	}
	if ctx.IsSet("challenge") {
		details.Challenge = ctx.String("challenge")
	}
	if ctx.IsSet("capabilities") {
		details.Capabilities = ctx.StringSlice("capabilities")
	}
	if ctx.IsSet("min-public-key-length") {
		details.MinimumPublicKeyLength = int32(ctx.Int("min-public-key-length"))
	}
	if ctx.IsSet("include-root") {
		details.IncludeRoot = ctx.Bool("include-root")
	}
	if ctx.IsSet("exclude-intermediate") {
		details.ExcludeIntermediate = ctx.Bool("exclude-intermediate")
	}
	if ctx.IsSet("encryption-algorithm-identifier") {
		details.EncryptionAlgorithmIdentifier = int32(ctx.Int("encryption-algorithm-identifier"))
	}

	decrypter := details.GetDecrypter()
	if decrypter == nil {
		decrypter = &linkedca.SCEPDecrypter{}
	}
	if ctx.IsSet("scep-decrypter-certificate-file") {
		decrypterCertificateFile := ctx.String("scep-decrypter-certificate-file")
		data, err := parseSCEPDecrypterCertificate(decrypterCertificateFile)
		if err != nil {
			return fmt.Errorf("failed parsing certificate from %q: %w", decrypterCertificateFile, err)
		}
		decrypter.Certificate = data
		details.Decrypter = decrypter
	}
	if ctx.IsSet("scep-decrypter-key-uri") {
		decrypter.KeyUri = ctx.String("scep-decrypter-key-uri")
		details.Decrypter = decrypter
	}
	if decrypterKeyFile := ctx.String("scep-decrypter-key-file"); decrypterKeyFile != "" {
		data, err := readSCEPDecrypterKey(decrypterKeyFile)
		if err != nil {
			return fmt.Errorf("failed reading decrypter key from %q: %w", decrypterKeyFile, err)
		}
		decrypter.Key = data
		details.Decrypter = decrypter
	}
	if decrypterKeyPasswordFile := ctx.String("scep-decrypter-key-password-file"); decrypterKeyPasswordFile != "" {
		decrypterKeyPassword, err := utils.ReadPasswordFromFile(decrypterKeyPasswordFile)
		if err != nil {
			return fmt.Errorf("failed reading decrypter key password from %q: %w", decrypterKeyPasswordFile, err)
		}
		decrypter.KeyPassword = decrypterKeyPassword
		details.Decrypter = decrypter
	}

	return nil
}
