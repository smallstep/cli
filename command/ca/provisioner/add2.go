package provisioner

import (
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
	"github.com/smallstep/certificates/linkedca"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func add2Command() cli.Command {
	return cli.Command{
		Name:   "add2",
		Action: cli.ActionFunc(add2Action),
		Usage:  "add a provisioner to the CA configuration",
		UsageText: `**step ca provisioner add** <name> <type> [**--create**] [**--private-key**=<file>]
[**--password-file**=<file>] [**--x509-template**=<file>] [**--ssh-template**=<file>]
[**--ssh**] [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "ssh",
				Usage: `Enable SSH on the new provisioners.`,
			},
			cli.StringFlag{
				Name:  "x509-template",
				Usage: `The x509 certificate template <file>, a JSON representation of the certificate to create.`,
			},
			cli.StringFlag{
				Name:  "ssh-template",
				Usage: `The x509 certificate template <file>, a JSON representation of the certificate to create.`,
			},

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
			flags.X5cCert,
			flags.X5cKey,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner add** adds a provisioner to the CA configuration.

## POSITIONAL ARGUMENTS

<name>
: The name of the provisioner.

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

func add2Action(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	x509TemplateFile := ctx.String("x509-template")
	sshTemplateFile := ctx.String("ssh-template")

	args := ctx.Args()

	p := &linkedca.Provisioner{
		Name: args.Get(0),
	}

	// Read x509 template if passed
	if x509TemplateFile != "" {
		b, err := utils.ReadFile(x509TemplateFile)
		if err != nil {
			return err
		}
		p.X509Template = b
	}
	if sshTemplateFile != "" {
		b, err := utils.ReadFile(sshTemplateFile)
		if err != nil {
			return err
		}
		p.SshTemplate = b
	}

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	switch args.Get(1) {
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
	default:
		return fmt.Errorf("unsupported provisioner type %s", args.Get(1))
	}
	if err != nil {
		return err
	}

	if p, err = client.CreateProvisioner(p); err != nil {
		return err
	}

	b, err := json.MarshalIndent(p, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling provisioner")
	}

	fmt.Println(string(b))
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
	jwkPubBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling JWK")
	}
	jwePrivStr, err := jwe.CompactSerialize()
	if err != nil {
		return nil, errors.Wrap(err, "error serializing JWE")
	}

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_JWK{
			JWK: &linkedca.JWKProvisioner{
				PublicKey:           jwkPubBytes,
				EncryptedPrivateKey: []byte(jwePrivStr),
			},
		},
	}, nil
}

func createACMEDetails(ctx *cli.Context) (*linkedca.ProvisionerDetails, error) {
	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_ACME{
			ACME: &linkedca.ACMEProvisioner{
				ForceCn: ctx.IsSet("forceCN"),
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
	if len(x5cRootFile) == 0 {
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
	pemKeysF := ctx.String("pem-keys")
	if len(pemKeysF) == 0 {
		return nil, errs.RequiredWithFlagValue(ctx, "type", "k8sSA", "pem-keys")
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

	return &linkedca.ProvisionerDetails{
		Data: &linkedca.ProvisionerDetails_OIDC{
			OIDC: &linkedca.OIDCProvisioner{
				ClientId:              clientID,
				ClientSecret:          ctx.String("client-secret"),
				ConfigurationEndpoint: confURL,
				Admins:                ctx.StringSlice("admin"),
				Domains:               ctx.StringSlice("domain"),
				ListenAddress:         ctx.String("listen-address"),
			},
		},
	}, nil
}
