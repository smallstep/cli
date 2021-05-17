package provisioner

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/mgmt"
	mgmtAPI "github.com/smallstep/certificates/authority/mgmt/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func add2Command() cli.Command {
	return cli.Command{
		Name:   "add2",
		Action: cli.ActionFunc(add2Action),
		Usage:  "add a provisioner to the CA configuration",
		UsageText: `**step ca provisioner add** <type> <name> [**--create**] [**--private-key**=<file>]
[**--password-file**=<file>] [**--ssh**] [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "ssh",
				Usage: `Enable SSH on the new provisioners.`,
			},
			flags.PasswordFile,

			// JWK provisioner flags
			cli.BoolFlag{
				Name:  "create",
				Usage: `Create the JWK key pair for the provisioner.`,
			},
			cli.StringFlag{
				Name:  "private-key",
				Usage: `The <file> containing the JWK private key.`,
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

			// X5C provisioner flags
			cli.StringFlag{
				Name: "x5c-root",
				Usage: `Root certificate (chain) <file> used to validate the signature on X5C
provisioning tokens.`,
			},
			// K8sSA provisioner flags
			cli.StringFlag{
				Name: "pem-keys",
				Usage: `Public key <file> for validating signatures on K8s Service Account Tokens.
PEM formatted bundle (can have multiple PEM blocks in the same file) of public
keys and x509 Certificates.`,
			},
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner add** adds a provisioner to the CA configuration.

## POSITIONAL ARGUMENTS

<type>
: The <type> of provisioner to create.

	<type> is a case-insensitive string and must be one of:

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

    **K8sSA**
    : Uses Kubernetes Service Account tokens.

    **SSHPOP**
    : Uses an SSH Certificate / private key pair to sign provisioning tokens.

<name>
: The name of the provisioner.

## EXAMPLES

Create a JWK provisioner:
'''
step ca provisioner add jane@doe.com --type JWK --ssh --public-key jwk.pub --private-key jwk.priv
'''

Create an OIDC provisioner:
'''
step ca provisioner add OIDC Google ---ssh \
	--client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
	--client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
	--configuration-endpoint https://accounts.google.com/.well-known/openid-configuration
'''

Create an X5C provisioner:
'''
step ca provisioner add X5C x5c --x5c-root x5c_ca.crt
'''

Create an ACME provisioner
'''
step ca provisioner add ACME acme
'''

Create an K8SSA provisioner:
'''
step ca provisioner add K8SSA kube --ssh --public-key key.pub
'''

Create an SSHPOP provisioner for renewing SSH host certificates:")
'''
step ca provisioner add SSHPOP sshpop
'''
`,
	}
}

var uuidRegexp = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// stringSlice is a flag.Value that allows to set multiple values.
type stringSlice struct {
	Values []string
}

func (s *stringSlice) String() string {
	if s != nil {
		return fmt.Sprint(s.Values)
	}
	return ""
}

func (s *stringSlice) Set(value string) error {
	s.Values = append(s.Values, value)
	return nil
}

func add2Action(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	typ := args.Get(0)
	name := args.Get(1)

	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return err
	}
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}
	rootFile := ctx.String("root")
	if len(rootFile) == 0 {
		rootFile = pki.GetRootCAPath()
		if _, err := os.Stat(rootFile); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	// Create online client
	var options []ca.ClientOption
	options = append(options, ca.WithRootFile(rootFile))
	client, err := ca.NewMgmtClient(caURL, options...)
	if err != nil {
		return err
	}

	var prov *mgmt.Provisioner
	switch mgmt.ProvisionerType(typ) {
	case mgmt.ProvisionerTypeJWK:
		prov, err = add2JWKProvisioner(ctx, client, name)
		/*
			case mgmt.ProvisionerTypeOIDC:
				return add2OIDCProvisioner(ctx, client, name)
			case mgmt.ProvisionerTypeX5C:
				return add2X5CProvisioner(ctx, client, name)
			case mgmt.ProvisionerTypeSSHPOP:
				return add2SSHPOPProvisioner(ctx, client, name)
			case mgmt.ProvisionerTypeK8SSA:
				return add2SSHPOPProvisioner(ctx, client, name)
			case mgmt.ProvisionerTypeACME:
				return add2ACMEProvisioner(ctx, client, name)
		*/
	default:
		return fmt.Errorf("unsupported provisioner type %s", typ)
	}
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(prov, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling provisioner")
	}

	fmt.Println(string(b))
	return nil
}

func add2JWKProvisioner(ctx *cli.Context, client *ca.MgmtClient, name string) (*mgmt.Provisioner, error) {
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
		pass, err := ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]", ui.WithValue(password))
		if err != nil {
			return nil, err
		}
		jwk, jwe, err = jose.GenerateDefaultKeyPair(pass)
		if err != nil {
			return nil, err
		}
	} else {
		jwkFile := ctx.String("private-key")
		if jwkFile == "" {
			return nil, errs.RequiredFlag(ctx, "private-key")
		}
		jwk, err = jose.ParseKey(jwkFile)
		if err != nil {
			return nil, errs.FileError(err, jwkFile)
		}
		// Only use asymmetric cryptography
		if _, ok := jwk.Key.([]byte); ok {
			return nil, errors.New("invalid JWK: a symmetric key cannot be used as a provisioner")
		}
		if jwk.IsPublic() {
			return nil, errors.New("invalid JWK: expected a private key")
		}
		// Create kid if not present
		if len(jwk.KeyID) == 0 {
			jwk.KeyID, err = jose.Thumbprint(jwk)
			if err != nil {
				return nil, err
			}
		}

		// Encrypt JWK
		jwe, err = jose.EncryptJWK(jwk)
		if err != nil {
			return nil, err
		}
	}

	details, err := mgmt.NewProvisionerDetails("JWK", mgmt.NewProvisionerCtx(mgmt.WithJWK(jwk, jwe)))
	if err != nil {
		return nil, errors.Wrap(err, "error generating JWK provisioner details")
	}
	detailBytes, err := json.Marshal(details)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling provisioner details")
	}

	return client.CreateProvisioner(&mgmtAPI.CreateProvisionerRequest{
		Type:    "JWK",
		Name:    name,
		Details: detailBytes,
	})
}
