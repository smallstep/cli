package provisioner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	nebula "github.com/slackhq/nebula/cert"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/linkedca"

	"github.com/smallstep/cli/command/ca/provisioner/webhook"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
)

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "provisioner",
		Usage:     "create and manage the certificate authority provisioners",
		UsageText: "step ca provisioner <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			getEncryptedKeyCommand(),
			addCommand(),
			updateCommand(),
			removeCommand(),
			webhook.Command(),
		},
		Description: `**step ca provisioner** command group provides facilities for managing the
certificate authority provisioners.

A provisioner is an entity that controls provisioning credentials, which are
used to generate provisioning tokens.

Provisioning credentials are simple JWK key pairs using public-key cryptography.
The public key is used to verify a provisioning token while the private key is
used to sign the provisioning token.

Provisioning tokens are JWT tokens signed by the JWK private key. These JWT
tokens are used to get a valid TLS certificate from the certificate authority.
Each provisioner is able to manage a different set of rules that can be used to
configure the bounds of the certificate.

In the certificate authority, a provisioner is configured with a JSON object
with the following properties:

* **name**: the provisioner name, it will become the JWT issuer and a good
  practice is to use an email address for this.
* **type**: the provisioner type, currently only "jwk" is supported.
* **key**: the JWK public key used to verify the provisioning tokens.
* **encryptedKey** (optional): the JWE compact serialization of the private key
  used to sign the provisioning tokens.
* **claims** (optional): an object with custom options for each provisioner.
  Options supported are:
  * **minTLSCertDuration**: minimum duration of a certificate, set to 5m by
    default.
  * **maxTLSCertDuration**: maximum duration of a certificate, set to 24h by
    default.
  * **defaultTLSCertDuration**: default duration of the certificate, set to 24h
    by default.
  * **disableRenewal**: whether or not to disable certificate renewal, set to false
    by default.

## EXAMPLES

List the active provisioners:
'''
$ step ca provisioner list
'''

Retrieve the encrypted private jwk for the given kid:
'''
$ step ca provisioner jwe-key 1234 --ca-url https://127.0.0.1 --root ./root.crt
'''

Add a single provisioner:
'''
$ step ca provisioner add max@smallstep.com max-laptop.jwk --ca-config ca.json
'''

Remove the provisioner matching a given issuer and kid:
'''
$ step ca provisioner remove max@smallstep.com --kid 1234 --ca-config ca.json
'''`,
	}
}

type crudClient interface {
	CreateProvisioner(prov *linkedca.Provisioner) (*linkedca.Provisioner, error)
	GetProvisioner(opts ...ca.ProvisionerOption) (*linkedca.Provisioner, error)
	UpdateProvisioner(name string, prov *linkedca.Provisioner) error
	RemoveProvisioner(opts ...ca.ProvisionerOption) error
}

func newCRUDClient(cliCtx *cli.Context, cfgFile string) (crudClient, error) {
	unauthAdminClient, err := cautils.NewUnauthenticatedAdminClient(cliCtx)
	if err != nil {
		return nil, fmt.Errorf("error generating admin client: %w", err)
	}

	var netErr *net.OpError

	err = unauthAdminClient.IsEnabled()
	switch {
	case errors.As(err, &netErr) || errors.Is(err, ca.ErrAdminAPINotImplemented):
		ui.PrintSelected("CA Configuration", cfgFile)
		cfg, err := config.LoadConfiguration(cfgFile)
		if err != nil {
			return nil, fmt.Errorf("error loading configuration: %w", err)
		}
		// Assume the ca.json is already valid to avoid enabling all the
		// features present in step-ca just to modify the provisioners.
		cfg.SkipValidation = true

		ui.Println()
		return newCaConfigClient(context.Background(), cfg, cfgFile)
	case errors.Is(err, ca.ErrAdminAPINotAuthorized):
		return cautils.NewAdminClient(cliCtx)
	default:
		return nil, err
	}
}

func parseInstanceAge(ctx *cli.Context) (age string, err error) {
	if !ctx.IsSet("instance-age") {
		return
	}
	age = ctx.String("instance-age")
	dur, err := time.ParseDuration(age)
	if err != nil {
		return "", err
	}
	if dur < 0 {
		return "", errs.MinSizeFlag(ctx, "instance-age", "0s")
	}
	return
}

func removeElements(list, rems []string) []string {
	if len(list) == 0 {
		return list
	}
	for _, rem := range rems {
		for i, elem := range list {
			if elem == rem {
				list[i] = list[len(list)-1]
				list = list[:len(list)-1]
				break
			}
		}
	}
	return list
}

var (
	x509TemplateFlag = cli.StringFlag{
		Name:  "x509-template",
		Usage: `The x509 certificate template <file>, a JSON representation of the certificate to create.`,
	}
	x509TemplateDataFlag = cli.StringFlag{
		Name:  "x509-template-data",
		Usage: `The x509 certificate template data <file>, a JSON map of data that can be used by the certificate template.`,
	}
	sshTemplateFlag = cli.StringFlag{
		Name:  "ssh-template",
		Usage: `The x509 certificate template <file>, a JSON representation of the certificate to create.`,
	}
	sshTemplateDataFlag = cli.StringFlag{
		Name:  "ssh-template-data",
		Usage: `The ssh certificate template data <file>, a JSON map of data that can be used by the certificate template.`,
	}
	x509MinDurFlag = cli.DurationFlag{
		Name: "x509-min-dur",
		Usage: `The minimum <duration> for an x509 certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	x509MaxDurFlag = cli.DurationFlag{
		Name: "x509-max-dur",
		Usage: `The maximum <duration> for an x509 certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	x509DefaultDurFlag = cli.DurationFlag{
		Name: "x509-default-dur",
		Usage: `The default <duration> for an x509 certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	sshUserMinDurFlag = cli.DurationFlag{
		Name: "ssh-user-min-dur",
		Usage: `The minimum <duration> for an ssh user certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	sshUserMaxDurFlag = cli.DurationFlag{
		Name: "ssh-user-max-dur",
		Usage: `The maximum <duration> for an ssh user certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	sshUserDefaultDurFlag = cli.DurationFlag{
		Name: "ssh-user-default-dur",
		Usage: `The maximum <duration> for an ssh user certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	sshHostMinDurFlag = cli.DurationFlag{
		Name: "ssh-host-min-dur",
		Usage: `The minimum <duration> for an ssh host certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	sshHostMaxDurFlag = cli.DurationFlag{
		Name: "ssh-host-max-dur",
		Usage: `The maximum <duration> for an ssh host certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	sshHostDefaultDurFlag = cli.DurationFlag{
		Name: "ssh-host-default-dur",
		Usage: `The maximum <duration> for an ssh host certificate generated by this provisioner.
Value must be a sequence of decimal numbers, each with optional fraction, and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	disableRenewalFlag = cli.BoolFlag{
		Name:  "disable-renewal",
		Usage: `Disable renewal for all certificates generated by this provisioner.`,
	}
	allowRenewalAfterExpiryFlag = cli.BoolFlag{
		Name:  "allow-renewal-after-expiry",
		Usage: `Allow renewals for expired certificates generated by this provisioner.`,
	}
	disableSmallstepExtensionsFlag = cli.BoolFlag{
		Name:  "disable-smallstep-extensions",
		Usage: `Disable the Smallstep extension for all certificates generated by this provisioner.`,
	}
	//enableX509Flag = cli.BoolFlag{
	//	Name:  "x509",
	//	Usage: `Enable provisioning of x509 certificates.`,
	//}
	enableSSHFlag = cli.BoolFlag{
		Name: "ssh",
		Usage: `Enable provisioning of ssh certificates. The default value is true. To
disable ssh use '--ssh=false'.`,
	}

	// General provisioner flags
	typeFlag = cli.StringFlag{
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
: Uses an X509 certificate / private key pair to sign provisioning tokens.

**K8SSA**
: Uses Kubernetes Service Account tokens.

**SSHPOP**
: Uses an SSH certificate / private key pair to sign provisioning tokens.

**SCEP**
: Uses the SCEP protocol to create certificates.

**Nebula**
: Uses a Nebula certificate / private key pair to sign provisioning tokens.
`}
	nameFlag = cli.StringFlag{
		Name:  "name",
		Usage: `The new <name> for the provisioner.`,
	}
	pubKeyFlag = cli.StringFlag{
		Name: "public-key",
		Usage: `The <file> containing the JWK public key. Or, a <file>
containing one or more PEM formatted keys, if used with the K8SSA provisioner.`,
	}

	// ACME and SCEP provisioner flags
	forceCNFlag = cli.BoolFlag{
		Name:  "force-cn",
		Usage: `Always set the common name in provisioned certificates.`,
	}

	challengeFlag = cli.StringSliceFlag{
		Name: "challenge",
		Usage: `With a SCEP provisioner the <challenge> is a shared secret between a
client and the CA.

With an ACME provisioner, this flag specifies the <challenge> or challenges to
enable. Use the flag multiple times to configure multiple challenges.

The supported ACME challenges are:

**http-01**
: With the HTTP challenge, the client in an ACME transaction proves its control
over a domain name by proving that it can provision HTTP resources on a server
accessible under that domain name.

**dns-01**
: With the DNS challenge, the client can prove control of a domain by
provisioning a TXT resource record containing a designated value for a specific
validation domain name.

**tls-alpn-01**
: With the TLS with Application-Layer Protocol Negotiation (TLS ALPN) challenge,
the client can prove control over a domain name by configuring a TLS server to
respond to specific connection attempts using the ALPN extension with
identifying information.

**device-attest-01**
: With the device attestation challenge, the client can prove control over a
permanent identifier of a device by providing an attestation statement
containing the identifier of the device.

If the provisioner has no challenges configured, http-01, dns-01 and tls-alpn-01
will be automatically enabled.`,
	}

	removeChallengeFlag = cli.StringSliceFlag{
		Name: "remove-challenge",
		Usage: `Remove an ACME <challenge> from the list configured in the provisioner.
Use the flag multiple times to remove multiple challenges.`,
	}

	// ACME provisioner flags
	requireEABFlag = cli.BoolFlag{
		Name: "require-eab",
		Usage: `Require (and enable) External Account Binding (EAB) for Account creation.
If this flag is set to false, then disable EAB.`,
	}

	attestationFormatFlag = cli.StringSliceFlag{
		Name: "attestation-format",
		Usage: `Enable an ACME attestation statement <format> in the provisioner. Use the flag
multiple times to configure multiple challenges.

The supported ACME attestation formats are:

**apple**
: With the apple format, Apple devices can use the device-attest-01 challenge to
get a new certificate.

**step**
: With the step format, devices like YubiKeys that can generate an attestation
certificate can use the device-attest-01 challenge to get a new certificate.

**tpm**
: With the tpm format, devices with TPMs can use the device-attest-01 challenge
to get a new certificate.`,
	}

	attestationRootsFlag = cli.StringSliceFlag{
		Name: "attestation-roots",
		Usage: `PEM-formatted root certificate(s) <file> used to validate the attestation
certificates. Use the flag multiple times to read from multiple files.`,
	}

	removeAttestationFormatFlag = cli.StringSliceFlag{
		Name: "remove-attestation-format",
		Usage: `Remove an ACME attestation statement <format> from the list configured in the provisioner.
Use the flag multiple times to remove multiple formats.`,
	}

	// SCEP provisioner flags
	scepCapabilitiesFlag = cli.StringSliceFlag{
		Name:  "capabilities",
		Usage: `The SCEP <capabilities> to advertise`,
	}
	scepIncludeRootFlag = cli.BoolFlag{
		Name:  "include-root",
		Usage: `Include the CA root certificate in the SCEP CA certificate chain`,
	}
	scepExcludeIntermediateFlag = cli.BoolFlag{
		Name:  "exclude-intermediate",
		Usage: `Exclude the CA intermediate certificate in the SCEP CA certificate chain`,
	}
	scepMinimumPublicKeyLengthFlag = cli.IntFlag{
		Name:  "min-public-key-length",
		Usage: `The minimum public key <length> of the SCEP RSA encryption key`,
	}
	scepEncryptionAlgorithmIdentifierFlag = cli.IntFlag{
		Name: "encryption-algorithm-identifier",
		Usage: `The <id> for the SCEP encryption algorithm to use.
		Valid values are 0 - 4, inclusive. The values correspond to:
		0: DES-CBC,
		1: AES-128-CBC,
		2: AES-256-CBC,
		3: AES-128-GCM,
		4: AES-256-GCM.
		Defaults to DES-CBC (0) for legacy clients.`,
	}

	scepDecrypterCertFileFlag = cli.StringFlag{
		Name:  "scep-decrypter-certificate-file",
		Usage: `The path to a PEM certificate <file> for the SCEP decrypter`,
	}
	scepDecrypterKeyFileFlag = cli.StringFlag{
		Name:  "scep-decrypter-key-file",
		Usage: `The path to a PEM private key <file> for the SCEP decrypter`,
	}
	scepDecrypterKeyURIFlag = cli.StringFlag{
		Name:  "scep-decrypter-key-uri",
		Usage: `The key <uri> for the SCEP decrypter. Should be a valid value for the KMS type used.`,
	}
	scepDecrypterKeyPasswordFileFlag = cli.StringFlag{
		Name:  "scep-decrypter-key-password-file",
		Usage: `The path to a <file> containing the password for the SCEP decrypter key`,
	}

	// Cloud provisioner flags
	awsAccountFlag = cli.StringSliceFlag{
		Name: "aws-account",
		Usage: `The AWS account <id> used to validate the identity documents.
Use the flag multiple times to configure multiple accounts.`,
	}
	removeAWSAccountFlag = cli.StringSliceFlag{
		Name: "remove-aws-account",
		Usage: `Remove an AWS account <id> used to validate the identity documents.
Use the flag multiple times to remove multiple accounts.`,
	}
	azureTenantFlag = cli.StringFlag{
		Name:  "azure-tenant",
		Usage: `The Microsoft Azure tenant <id> used to validate the identity tokens.`,
	}
	azureResourceGroupFlag = cli.StringSliceFlag{
		Name: "azure-resource-group",
		Usage: `The Microsoft Azure resource group <name> used to validate the identity tokens.
Use the flag multiple times to configure multiple resource groups`,
	}
	removeAzureResourceGroupFlag = cli.StringSliceFlag{
		Name: "remove-azure-resource-group",
		Usage: `Remove a Microsoft Azure resource group <name> used to validate the identity tokens.
Use the flag multiple times to configure multiple resource groups`,
	}
	azureAudienceFlag = cli.StringFlag{
		Name:  "azure-audience",
		Usage: `The Microsoft Azure audience <name> used to validate the identity tokens.`,
	}
	azureSubscriptionIDFlag = cli.StringSliceFlag{
		Name: "azure-subscription-id",
		Usage: `The Microsoft Azure subscription <id> used to validate the identity tokens.
Use the flag multiple times to configure multiple subscription IDs`,
	}
	removeAzureSubscriptionIDFlag = cli.StringSliceFlag{
		Name: "remove-azure-subscription-id",
		Usage: `Remove a Microsoft Azure subscription <id> used to validate the identity tokens.
Use the flag multiple times to configure multiple subscription IDs`,
	}
	azureObjectIDFlag = cli.StringSliceFlag{
		Name: "azure-object-id",
		Usage: `The Microsoft Azure AD object <id> used to validate the identity tokens.
Use the flag multiple times to configure multiple object IDs`,
	}
	removeAzureObjectIDFlag = cli.StringSliceFlag{
		Name: "remove-azure-object-id",
		Usage: `Remove a Microsoft Azure AD object <id> used to validate the identity tokens.
Use the flag multiple times to remove multiple object IDs`,
	}
	gcpServiceAccountFlag = cli.StringSliceFlag{
		Name: "gcp-service-account",
		Usage: `The Google service account <email> or <id> used to validate the identity tokens.
Use the flag multiple times to configure multiple service accounts.`,
	}
	removeGCPServiceAccountFlag = cli.StringSliceFlag{
		Name: "remove-gcp-service-account",
		Usage: `Remove a Google service account <email> or <id> used to validate the identity tokens.
Use the flag multiple times to remove multiple service accounts.`,
	}
	gcpProjectFlag = cli.StringSliceFlag{
		Name: "gcp-project",
		Usage: `The Google project <id> used to validate the identity tokens.
Use the flag multiple times to configure multiple projects`,
	}
	removeGCPProjectFlag = cli.StringSliceFlag{
		Name: "remove-gcp-project",
		Usage: `Remove a Google project <id> used to validate the identity tokens.
Use the flag multiple times to remove multiple projects`,
	}
	instanceAgeFlag = cli.DurationFlag{
		Name: "instance-age",
		Usage: `The maximum <duration> to grant a certificate in AWS and GCP provisioners.
A <duration> is sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}
	/*
			awsIIDRootsFlag = cli.StringFlag{
				Name: "iid-roots",
				Usage: `The <file> containing the certificates used to validate the
		instance identity documents in AWS.`,
			}
	*/
	disableCustomSANsFlag = cli.BoolFlag{
		Name: "disable-custom-sans",
		Usage: `On cloud provisioners, if enabled only the internal DNS and IP will be added as a SAN.
By default it will accept any SAN in the CSR.`,
	}
	disableTOFUFlag = cli.BoolFlag{
		Name: "disable-trust-on-first-use,disable-tofu",
		Usage: `On cloud provisioners, if enabled multiple sign request for this provisioner
with the same instance will be accepted. By default only the first request
will be accepted.`,
	}

	// Nebula provisioner flags
	nebulaRootFlag = cli.StringFlag{
		Name: "nebula-root",
		Usage: `Root certificate (chain) <file> used to validate the signature on Nebula
provisioning tokens.`,
	}

	// JWK provisioner flags
	jwkCreateFlag = cli.BoolFlag{
		Name:  "create",
		Usage: `Create the JWK key pair for the provisioner.`,
	}
	jwkPrivKeyFlag = cli.StringFlag{
		Name:  "private-key",
		Usage: `The <file> containing the JWK private key.`,
	}

	// OIDC provisioner flags
	oidcClientIDFlag = cli.StringFlag{
		Name:  "client-id",
		Usage: `The <id> used to validate the audience in an OpenID Connect token.`,
	}
	oidcClientSecretFlag = cli.StringFlag{
		Name:  "client-secret",
		Usage: `The <secret> used to obtain the OpenID Connect tokens.`,
	}
	oidcListenAddressFlag = cli.StringFlag{
		Name:  "listen-address",
		Usage: `The callback <address> used in the OpenID Connect flow (e.g. \":10000\")`,
	}
	oidcConfigEndpointFlag = cli.StringFlag{
		Name:  "configuration-endpoint",
		Usage: `OpenID Connect configuration <url>.`,
	}
	oidcAdminFlag = cli.StringSliceFlag{
		Name: "admin",
		Usage: `The <email> of an admin user in an OpenID Connect provisioner, this user
will not have restrictions in the certificates to sign. Use the
'--admin' flag multiple times to configure multiple administrators.`,
	}
	oidcRemoveAdminFlag = cli.StringSliceFlag{
		Name: "remove-admin",
		Usage: `Remove the <email> of an admin user in an OpenID Connect provisioner, this user
will not have restrictions in the certificates to sign. Use the
'--remove-admin' flag multiple times to remove multiple administrators.`,
	}
	oidcDomainFlag = cli.StringSliceFlag{
		Name: "domain",
		Usage: `The <domain> used to validate the email claim in an OpenID Connect provisioner.
Use the '--domain' flag multiple times to configure multiple domains.`,
	}
	oidcRemoveDomainFlag = cli.StringSliceFlag{
		Name: "remove-domain",
		Usage: `Remove the <domain> used to validate the email claim in an OpenID Connect provisioner.
Use the '--remove-domain' flag multiple times to remove multiple domains.`,
	}
	oidcGroupFlag = cli.StringSliceFlag{
		Name: "group",
		Usage: `The <group> list used to validate the groups extension in an OpenID Connect token.
Use the '--group' flag multiple times to configure multiple groups.`,
	}
	oidcTenantIDFlag = cli.StringFlag{
		Name:  "tenant-id",
		Usage: `The <tenant-id> used to replace the templatized tenantid value in the OpenID Configuration.`,
	}
	oidcScopeFlag = cli.StringSliceFlag{
		Name: "scope",
		Usage: `The <scope> list used to validate the scopes extension in an OpenID Connect token.
Use the '--scope' flag multiple times to configure multiple scopes.`,
	}
	oidcRemoveScopeFlag = cli.StringSliceFlag{
		Name: "remove-scope",
		Usage: `Remove the <scope> used to validate the scopes extension in an OpenID Connect token.
Use the '--remove-scope' flag multiple times to remove multiple scopes.`,
	}
	oidcAuthParamFlag = cli.StringSliceFlag{
		Name: "auth-param",
		Usage: `The <auth-param> list used to validate the auth-params extension in an OpenID Connect token.
Use the '--auth-param' flag multiple times to configure multiple auth-params.`,
	}

	// X5C provisioner flags
	x5cRootsFlag = cli.StringFlag{
		Name: "x5c-roots, x5c-root",
		Usage: `PEM-formatted root certificate(s) <file> used to validate the signature on X5C
provisioning tokens.`,
	}
)

func readNebulaRoots(rootFile string) ([][]byte, error) {
	b, err := utils.ReadFile(rootFile)
	if err != nil {
		return nil, err
	}

	var crt *nebula.NebulaCertificate
	var certs []*nebula.NebulaCertificate
	for len(b) > 0 {
		crt, b, err = nebula.UnmarshalNebulaCertificateFromPEM(b)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading %s", rootFile)
		}
		if crt.Details.IsCA {
			certs = append(certs, crt)
		}
	}
	if len(certs) == 0 {
		return nil, errors.Errorf("error reading %s: no CA certificates found", rootFile)
	}

	rootBytes := make([][]byte, len(certs))
	for i, crt := range certs {
		b, err = crt.MarshalToPEM()
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling certificate")
		}
		rootBytes[i] = b
	}

	return rootBytes, nil
}
