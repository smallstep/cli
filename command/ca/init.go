package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/kms"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"

	// Enable azurekms
	_ "github.com/smallstep/certificates/kms/azurekms"

	"go.step.sm/cli-utils/command"
)

func initCommand() cli.Command {
	return cli.Command{
		Name:   "init",
		Action: cli.ActionFunc(initAction),
		Usage:  "initialize the CA PKI",
		UsageText: `**step ca init**
[**--root**=<file>] [**--key**=<file>] [**--pki**] [**--ssh**]
[**--helm**] [**--deployment-type**=<name>] [**--name**=<name>]
[**--dns**=<dns>] [**--address**=<address>] [**--provisioner**=<name>]
[**--provisioner-password-file**=<file>] [**--password-file**=<file>]
[**--with-ca-url**=<url>] [**--ra**=<type>] [**--kms**=<type>] [**--no-db**]`,
		Description: `**step ca init** command initializes a public key infrastructure (PKI) to be
 used by the Certificate Authority.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "root",
				Usage:  "The path of an existing PEM <file> to be used as the root certificate authority.",
				EnvVar: command.IgnoreEnvVar,
			},
			cli.StringFlag{
				Name:   "key",
				Usage:  "The path of an existing key <file> of the root certificate authority.",
				EnvVar: command.IgnoreEnvVar,
			},
			cli.BoolFlag{
				Name:  "pki",
				Usage: "Generate only the PKI without the CA configuration.",
			},
			cli.BoolFlag{
				Name:  "ssh",
				Usage: `Create keys to sign SSH certificates.`,
			},
			cli.BoolFlag{
				Name:  "helm",
				Usage: `Generates a Helm values YAML to be used with step-certificates chart.`,
			},
			cli.StringFlag{
				Name: "deployment-type",
				Usage: `The <name> of the deployment type to use. Options are:
    **standalone**
    :  An instance of step-ca that does not connect to any cloud services. You
    manage authority keys and configuration yourself.
    Choose standalone if you'd like to run step-ca yourself and do not want
    cloud services or commercial support.

    **linked**
    :  An instance of step-ca with locally managed keys that connects to your
    Certificate Manager account for provisioner management, alerting,
    reporting, revocation, and other managed services.
    Choose linked if you'd like cloud services and support, but need to
    control your authority's signing keys.

    **hosted**
    :  A highly available, fully-managed instance of step-ca run by smallstep
    just for you.
    Choose hosted if you'd like cloud services and support.

: More information and pricing at: https://u.step.sm/cm`,
			},
			cli.StringFlag{
				Name:  "name",
				Usage: "The <name> of the new PKI.",
			},
			cli.StringSliceFlag{
				Name: "dns",
				Usage: `The DNS <name> or IP address of the new CA.
Use the '--dns' flag multiple times to configure multiple DNS names.`,
			},
			cli.StringFlag{
				Name:  "address",
				Usage: "The <address> that the new CA will listen at.",
			},
			cli.StringFlag{
				Name:  "provisioner",
				Usage: "The <name> of the first provisioner.",
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to encrypt the keys.`,
			},
			cli.StringFlag{
				Name:  "provisioner-password-file",
				Usage: `The path to the <file> containing the password to encrypt the provisioner key.`,
			},
			cli.StringFlag{
				Name:  "with-ca-url",
				Usage: `<URI> of the Step Certificate Authority to write in defaults.json`,
			},
			cli.StringFlag{
				Name:  "ra",
				Usage: `The registration authority <type> to use. Currently "StepCAS" and "CloudCAS" are supported.`,
			},
			cli.StringFlag{
				Name: "kms",
				Usage: `The key manager service <type> to use to manage keys. Options are:
	**azurekms**
    :  Use Azure Key Vault to manage X.509 and SSH keys. The key URIs have
	the following format <azurekms:name=key-name;vault=vault-name>.`,
			},
			cli.StringFlag{
				Name: "issuer",
				Usage: `The registration authority issuer <url> to use.

: If StepCAS is used, this flag should be the URL of the CA to connect
to, e.g https://ca.smallstep.com:9000

: If CloudCAS is used, this flag should be the resource name of the
intermediate certificate to use. This has the format
'projects/\\*/locations/\\*/caPools/\\*/certificateAuthorities/\\*'.`,
			},
			cli.StringFlag{
				Name: "issuer-fingerprint",
				Usage: `The root certificate <fingerprint> of the issuer CA.
This flag is supported in "StepCAS", and it should be the result of running:
'''
$ step certificate fingerprint root_ca.crt
4fe5f5ef09e95c803fdcb80b8cf511e2a885eb86f3ce74e3e90e62fa3faf1531
'''`,
			},
			cli.StringFlag{
				Name: "issuer-provisioner",
				Usage: `The <name> of an existing provisioner in the issuer CA.
This flag is supported in "StepCAS".`,
			},
			cli.StringFlag{
				Name: "credentials-file",
				Usage: `The registration authority credentials <file> to use.

: If CloudCAS is used, this flag should be the path to a service account key.
It can also be set using the 'GOOGLE_APPLICATION_CREDENTIALS=path'
environment variable or the default service account in an instance in Google
Cloud.`,
			},
			cli.BoolFlag{
				Name:  "no-db",
				Usage: `Generate a CA configuration without the DB stanza. No persistence layer.`,
			},
		},
	}
}

func initAction(ctx *cli.Context) (err error) {
	if err := assertCryptoRand(); err != nil {
		return err
	}

	var rootCrt *x509.Certificate
	var rootKey interface{}

	caURL := ctx.String("with-ca-url")
	root := ctx.String("root")
	key := ctx.String("key")
	ra := strings.ToLower(ctx.String("ra"))
	kmsName := strings.ToLower(ctx.String("kms"))
	pkiOnly := ctx.Bool("pki")
	noDB := ctx.Bool("no-db")
	helm := ctx.Bool("helm")

	switch {
	case root != "" && key == "":
		return errs.RequiredWithFlag(ctx, "root", "key")
	case root == "" && key != "":
		return errs.RequiredWithFlag(ctx, "key", "root")
	case root != "" && key != "":
		if rootCrt, err = pemutil.ReadCertificate(root); err != nil {
			return err
		}
		if rootKey, err = pemutil.Read(key); err != nil {
			return err
		}
	case ra != "" && ra != apiv1.CloudCAS && ra != apiv1.StepCAS:
		return errs.InvalidFlagValue(ctx, "ra", ctx.String("ra"), "StepCAS or CloudCAS")
	case kmsName != "" && kmsName != "azurekms":
		return errs.InvalidFlagValue(ctx, "kms", ctx.String("kms"), "azurekms")
	case kmsName != "" && ra != "":
		return errs.IncompatibleFlagWithFlag(ctx, "kms", "ra")
	case pkiOnly && noDB:
		return errs.IncompatibleFlagWithFlag(ctx, "pki", "no-db")
	case pkiOnly && helm:
		return errs.IncompatibleFlagWithFlag(ctx, "pki", "helm")
	}

	var password string
	if passwordFile := ctx.String("password-file"); passwordFile != "" {
		password, err = utils.ReadStringPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	// Provisioner password will be equal to the certificate private keys if
	// --provisioner-password-file is not provided.
	var provisionerPassword []byte
	if passwordFile := ctx.String("provisioner-password-file"); passwordFile != "" {
		provisionerPassword, err = utils.ReadPasswordFromFile(passwordFile)
		if err != nil {
			return err
		}
	}

	// Common for both CA and RA

	var name, org, resource string
	var casOptions apiv1.Options
	var deploymentType pki.DeploymentType
	var opts []pki.Option
	switch ra {
	case apiv1.CloudCAS:
		var create bool
		var project, location, caPool, caPoolTier, gcsBucket string

		caPoolTiers := []struct {
			Name  string
			Value string
		}{{"DevOps", "DEVOPS"}, {"Enterprise", "ENTERPRISE"}}

		// Prompt or get deployment type from flag
		deploymentType, err = promptDeploymentType(ctx, true)
		if err != nil {
			return err
		}

		iss := ctx.String("issuer")
		if iss == "" {
			create, err = ui.PromptYesNo("Would you like to create a new PKI (y) or use an existing one (n)?")
			if err != nil {
				return err
			}
			if create {
				ui.Println("What would you like to name your new PKI?", ui.WithValue(ctx.String("name")))
				name, err = ui.Prompt("(e.g. Smallstep)",
					ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("name")))
				if err != nil {
					return err
				}
				ui.Println("What is the name of your organization?")
				org, err = ui.Prompt("(e.g. Smallstep)",
					ui.WithValidateNotEmpty())
				if err != nil {
					return err
				}
				ui.Println("What resource id do you want to use? [we will append -Root-CA or -Intermediate-CA]")
				resource, err = ui.Prompt("(e.g. Smallstep)",
					ui.WithValidateRegexp("^[a-zA-Z0-9-_]+$"))
				if err != nil {
					return err
				}
				ui.Println("What is the id of your project on Google's Cloud Platform?")
				project, err = ui.Prompt("(e.g. smallstep-ca)",
					ui.WithValidateRegexp("^[a-z][a-z0-9-]{4,28}[a-z0-9]$"))
				if err != nil {
					return err
				}
				ui.Println("What region or location do you want to use?")
				location, err = ui.Prompt("(e.g. us-west1)",
					ui.WithValidateRegexp("^[a-z0-9-]+$"))
				if err != nil {
					return err
				}
				ui.Println("What CA pool name do you want to use?")
				caPool, err = ui.Prompt("(e.g. Smallstep)",
					ui.WithValidateRegexp("^[a-zA-Z0-9_-]{1,63}"))
				if err != nil {
					return err
				}
				i, _, err := ui.Select("What CA pool tier do you want to use?", caPoolTiers, ui.WithSelectTemplates(ui.NamedSelectTemplates("Tier")))
				if err != nil {
					return err
				}
				caPoolTier = caPoolTiers[i].Value
				ui.Println("What GCS bucket do you want to use? Leave it empty to use a managed one.")
				gcsBucket, err = ui.Prompt("(e.g. my-bucket)", ui.WithValidateRegexp("(^$)|(^[a-z0-9._-]{3,222}$)"))
				if err != nil {
					return err
				}
			} else {
				ui.Println("What certificate authority would you like to use?")
				iss, err = ui.Prompt("(e.g. projects/smallstep-ca/locations/us-west1/caPools/smallstep/certificateAuthorities/intermediate-ca)",
					ui.WithValidateRegexp("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/caPools/[a-zA-Z0-9-_]+/certificateAuthorities/[a-zA-Z0-9-_]+$"))
				if err != nil {
					return err
				}
			}
		}
		casOptions = apiv1.Options{
			Type:                 apiv1.CloudCAS,
			CredentialsFile:      ctx.String("credentials-file"),
			CertificateAuthority: iss,
			IsCreator:            create,
			Project:              project,
			Location:             location,
			CaPool:               caPool,
			CaPoolTier:           caPoolTier,
			GCSBucket:            gcsBucket,
		}
	case apiv1.StepCAS:
		deploymentType, err = promptDeploymentType(ctx, true)
		if err != nil {
			return err
		}
		ui.Println("What is the url of your CA?", ui.WithValue(ctx.String("issuer")))
		ca, err := ui.Prompt("(e.g. https://ca.smallstep.com:9000)",
			ui.WithValidateRegexp("(?i)^https://.+$"), ui.WithValue(ctx.String("issuer")))
		if err != nil {
			return err
		}
		ui.Println("What is the fingerprint of the CA's root file?", ui.WithValue(ctx.String("issuer-fingerprint")))
		fingerprint, err := ui.Prompt("(e.g. 4fe5f5ef09e95c803fdcb80b8cf511e2a885eb86f3ce74e3e90e62fa3faf1531)",
			ui.WithValidateRegexp("^[a-fA-F0-9]{64}$"), ui.WithValue(ctx.String("issuer-fingerprint")))
		if err != nil {
			return err
		}
		ui.Println("What is the JWK provisioner you want to use?", ui.WithValue(ctx.String("issuer-provisioner")))
		provisioner, err := ui.Prompt("(e.g. you@smallstep.com)",
			ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("issuer-provisioner")))
		if err != nil {
			return err
		}
		casOptions = apiv1.Options{
			Type:                            apiv1.StepCAS,
			IsCreator:                       false,
			IsCAGetter:                      true,
			CertificateAuthority:            ca,
			CertificateAuthorityFingerprint: fingerprint,
			CertificateIssuer: &apiv1.CertificateIssuer{
				Type:        "JWK",
				Provisioner: provisioner,
			},
		}
	default:
		deploymentType, err = promptDeploymentType(ctx, false)
		if err != nil {
			return err
		}
		if deploymentType == pki.HostedDeployment {
			ui.Println()
			ui.Println("Sorry, we can't create hosted authorities from the CLI yet. To create a hosted")
			ui.Println("authority please visit:\n")
			ui.Println("    \033[1mhttps://u.step.sm/hosted\033[0m\n")
			ui.Println("To connect to an existing hosted authority run:\n")
			ui.Println("    $ step ca bootstrap --team <name> --authority <authority>")
			ui.Println()
			return nil
		}

		ui.Println("What would you like to name your new PKI?", ui.WithValue(ctx.String("name")))
		name, err = ui.Prompt("(e.g. Smallstep)", ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("name")))
		if err != nil {
			return err
		}

		// Get names for key managers keys.
		// Currently only azure is supported.
		var keyManager kms.KeyManager
		if kmsName != "" {
			var rootURI, intermediateURI, sshHostURI, sshUserURI string
			keyManager, err = kms.New(context.Background(), kms.Options{
				Type: kmsName,
			})
			if err != nil {
				return err
			}

			var validateFunc func(s string) error
			if v, ok := keyManager.(interface{ ValidateName(s string) error }); ok {
				validateFunc = v.ValidateName
			} else {
				validateFunc = func(s string) error {
					return nil
				}
			}

			if rootKey == nil {
				ui.Println("What URI would you like to use for the root certificate key?")
				rootURI, err = ui.Prompt("(e.g. azurekms:name=my-root-key;vault=my-vault)", ui.WithValidateFunc(validateFunc))
				if err != nil {
					return err
				}
			}

			ui.Println("What URI would you like to use for the intermediate certificate key?")
			intermediateURI, err = ui.Prompt("(e.g. azurekms:name=my-intermediate-key;vault=my-vault)", ui.WithValidateFunc(validateFunc))
			if err != nil {
				return err
			}

			if ctx.Bool("ssh") {
				ui.Println("What URI would you like to use for the SSH host key?")
				sshHostURI, err = ui.Prompt("(e.g. azurekms:name=my-host-key;vault=my-vault)", ui.WithValidateFunc(validateFunc))
				if err != nil {
					return err
				}

				ui.Println("What URI would you like to use for the SSH user key?")
				sshUserURI, err = ui.Prompt("(e.g. azurekms:name=my-user-key;vault=my-vault)", ui.WithValidateFunc(validateFunc))
				if err != nil {
					return err
				}
			}

			// Add uris to the pki options. Empty URIs will be ignored.
			opts = append(opts, pki.WithKMS(kmsName),
				pki.WithKeyURIs(rootURI, intermediateURI, sshHostURI, sshUserURI))
		}

		// set org and resource to pki name
		org, resource = name, name

		casOptions = apiv1.Options{
			Type:       apiv1.SoftCAS,
			IsCreator:  true,
			KeyManager: keyManager,
		}
	}

	if pkiOnly {
		opts = append(opts, pki.WithPKIOnly())
	} else {
		ui.Println("What DNS names or IP addresses would you like to add to your new CA?", ui.WithSliceValue(ctx.StringSlice("dns")))
		dnsValue, err := ui.Prompt("(e.g. ca.smallstep.com[,1.1.1.1,etc.])", ui.WithSliceValue(ctx.StringSlice("dns")))
		if err != nil {
			return err
		}
		var (
			dnsValidator = ui.DNS()
			dnsNames     []string
		)
		dnsValue = strings.ReplaceAll(dnsValue, " ", ",")
		parts := strings.Split(dnsValue, ",")
		for _, name := range parts {
			if name == "" {
				continue
			}
			if err := dnsValidator(name); err != nil {
				return err
			}
			dnsNames = append(dnsNames, strings.TrimSpace(name))
		}

		var address string
		ui.Println("What IP and port will your new CA bind to?", ui.WithValue(ctx.String("address")))
		address, err = ui.Prompt("(e.g. :443 or 127.0.0.1:443)",
			ui.WithValidateFunc(ui.Address()), ui.WithValue(ctx.String("address")))
		if err != nil {
			return err
		}

		var provisioner string
		// Only standalone deployments will create an initial provisioner.
		// Linked or hosted deployments will use an OIDC token as the first
		// deployment.
		if deploymentType == pki.StandaloneDeployment {
			ui.Println("What would you like to name the CA's first provisioner?", ui.WithValue(ctx.String("provisioner")))
			provisioner, err = ui.Prompt("(e.g. you@smallstep.com)",
				ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("provisioner")))
			if err != nil {
				return err
			}
		}

		opts = append(opts,
			pki.WithAddress(address),
			pki.WithCaURL(caURL),
			pki.WithDNSNames(dnsNames),
			pki.WithDeploymentType(deploymentType),
		)
		if deploymentType == pki.StandaloneDeployment {
			opts = append(opts, pki.WithProvisioner(provisioner))
		}
		if deploymentType == pki.LinkedDeployment {
			opts = append(opts, pki.WithAdmin())
		} else if ctx.Bool("ssh") {
			opts = append(opts, pki.WithSSH())
		}
		if noDB {
			opts = append(opts, pki.WithNoDB())
		}
		if helm {
			opts = append(opts, pki.WithHelm())
		}
	}

	p, err := pki.New(casOptions, opts...)
	if err != nil {
		return err
	}

	if ra != "" || kmsName != "" {
		// RA mode will not have encrypted keys. With the exception of SSH keys,
		// but this is not common on RA mode.
		ui.Println("Choose a password for your first provisioner.", ui.WithValue(password))
	} else {
		// Linked CAs will use OIDC as a first provisioner.
		if pkiOnly || deploymentType != pki.StandaloneDeployment {
			ui.Println("Choose a password for your CA keys.", ui.WithValue(password))
		} else {
			ui.Println("Choose a password for your CA keys and first provisioner.", ui.WithValue(password))
		}
	}

	pass, err := ui.PromptPasswordGenerate("[leave empty and we'll generate one]", ui.WithRichPrompt(), ui.WithValue(password))
	if err != nil {
		return err
	}

	if !pkiOnly && deploymentType == pki.StandaloneDeployment {
		// Generate provisioner key pairs.
		if len(provisionerPassword) > 0 {
			if err := p.GenerateKeyPairs(provisionerPassword); err != nil {
				return err
			}
		} else {
			if err := p.GenerateKeyPairs(pass); err != nil {
				return err
			}
		}
	}

	if casOptions.IsCreator {
		var root *apiv1.CreateCertificateAuthorityResponse
		ui.Println()
		// Generate root certificate if not set.
		if rootCrt == nil && rootKey == nil {
			ui.Print("Generating root certificate... ")
			root, err = p.GenerateRootCertificate(name, org, resource, pass)
			if err != nil {
				return err
			}
			ui.Println("done!")
		} else {
			ui.Printf("Copying root certificate... ")
			// Do not copy key in STEPPATH
			if err := p.WriteRootCertificate(rootCrt, nil, nil); err != nil {
				return err
			}
			root = p.CreateCertificateAuthorityResponse(rootCrt, rootKey)
			ui.Println("done!")
		}

		// Always generate the intermediate certificate
		ui.Printf("Generating intermediate certificate... ")
		time.Sleep(1 * time.Second)
		err = p.GenerateIntermediateCertificate(name, org, resource, root, pass)
		if err != nil {
			return err
		}
		ui.Println("done!")
	} else if err := p.GetCertificateAuthority(); err != nil {
		// Attempt to get the root certificate from RA.
		return err
	}

	if ctx.Bool("ssh") {
		ui.Printf("Generating user and host SSH certificate signing keys... ")
		if err := p.GenerateSSHSigningKeys(pass); err != nil {
			return err
		}
		ui.Println("done!")
	}

	if helm {
		return p.WriteHelmTemplate(os.Stdout)
	}
	return p.Save()
}

func isNonInteractiveInit(ctx *cli.Context) bool {
	var pkiFlags []string
	configFlags := []string{
		"dns", "address", "provisioner",
	}
	switch strings.ToLower(ctx.String("ra")) {
	case apiv1.CloudCAS:
		pkiFlags = []string{"issuer"}
		configFlags = append(configFlags, "password-file")
	case apiv1.StepCAS:
		pkiFlags = []string{"issuer", "issuer-fingerprint", "issuer-provisioner"}
		configFlags = append(configFlags, "password-file")
	default:
		pkiFlags = []string{"name", "password-file"}
	}

	for _, s := range pkiFlags {
		if ctx.String(s) == "" {
			return false
		}
	}

	// If not pki only, then require all config flags.
	if !ctx.Bool("pki") {
		for _, s := range configFlags {
			if ctx.String(s) == "" {
				return false
			}
		}
	}

	return true
}

func promptDeploymentType(ctx *cli.Context, isRA bool) (pki.DeploymentType, error) {
	type deployment struct {
		Name        string
		Description string
		Value       pki.DeploymentType
	}

	var deploymentTypes []deployment
	deploymentType := strings.ToLower(ctx.String("deployment-type"))

	// Assume standalone for backward compatibility if all required flags are
	// passed.
	if deploymentType == "" && isNonInteractiveInit(ctx) {
		return pki.StandaloneDeployment, nil
	}

	deploymentTypes = []deployment{
		{"Standalone", "step-ca instance you run yourself", pki.StandaloneDeployment},
		{"Linked", "standalone, plus cloud configuration, reporting & alerting", pki.LinkedDeployment},
		{"Hosted", "fully-managed step-ca cloud instance run for you by smallstep", pki.HostedDeployment},
	}

	if isRA {
		switch deploymentType {
		case "":
			// Deployment type Hosted is not supported for RAs
			deploymentTypes = deploymentTypes[:2]
		case "standalone":
			return pki.StandaloneDeployment, nil
		case "linked":
			return pki.LinkedDeployment, nil
		default:
			return 0, errs.InvalidFlagValue(ctx, "deployment-type", deploymentType, "standalone or linked")
		}
	} else {
		switch deploymentType {
		case "":
		case "standalone":
			return pki.StandaloneDeployment, nil
		case "linked":
			return pki.LinkedDeployment, nil
		case "hosted":
			return pki.HostedDeployment, nil
		default:
			return 0, errs.InvalidFlagValue(ctx, "deployment-type", deploymentType, "standalone, linked or hosted")
		}
	}

	i, _, err := ui.Select("What deployment type would you like to configure?", deploymentTypes,
		ui.WithSelectTemplates(&promptui.SelectTemplates{
			Active:   fmt.Sprintf("%s {{ printf \"%%s - %%s\" .Name .Description | underline }}", ui.IconSelect),
			Inactive: "  {{ .Name }} - {{ .Description }}",
			Selected: fmt.Sprintf(`{{ "%s" | green }} {{ "Deployment Type:" | bold }} {{ .Name }}`, ui.IconGood),
		}))
	if err != nil {
		return 0, err
	}
	return deploymentTypes[i].Value, nil
}

// assertCryptoRand asserts that a cryptographically secure random number
// generator is available, it will return an error otherwise.
func assertCryptoRand() error {
	buf := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return errs.NewError("crypto/rand is unavailable: Read() failed with %#v", err)
	}
	return nil
}
