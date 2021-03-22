package ca

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func initCommand() cli.Command {
	return cli.Command{
		Name:   "init",
		Action: cli.ActionFunc(initAction),
		Usage:  "initialize the CA PKI",
		UsageText: `**step ca init**
[**--root**=<path>] [**--key**=<path>] [**--pki**] [**--ssh**] [**--name**=<name>]
[**--dns**=<dns>] [**--address**=<address>] [**--provisioner**=<name>]
[**--provisioner-password-file**=<path>] [**--password-file**=<path>]
[**--with-ca-url**=<url>] [**--no-db**]`,
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
			cli.StringFlag{
				Name:  "name",
				Usage: "The <name> of the new PKI.",
			},
			cli.StringFlag{
				Name:  "dns",
				Usage: "The comma separated DNS <names> or IP addresses of the new CA.",
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
				Usage: `The registration authority <name> to use. Currently only "CloudCAS" is supported.`,
			},
			cli.StringFlag{
				Name: "issuer",
				Usage: `The registration authority issuer <name> to use.

: If CloudCAS is used, this flag should be the resource name of the
intermediate certificate to use. This has the format
'projects/\\*/locations/\\*/certificateAuthorities/\\*'.`,
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
	if err = assertCryptoRand(); err != nil {
		return err
	}

	var rootCrt *x509.Certificate
	var rootKey interface{}

	caURL := ctx.String("with-ca-url")
	root := ctx.String("root")
	key := ctx.String("key")
	ra := strings.ToLower(ctx.String("ra"))
	switch {
	case len(root) > 0 && len(key) == 0:
		return errs.RequiredWithFlag(ctx, "root", "key")
	case len(root) == 0 && len(key) > 0:
		return errs.RequiredWithFlag(ctx, "key", "root")
	case len(root) > 0 && len(key) > 0:
		if rootCrt, err = pemutil.ReadCertificate(root); err != nil {
			return err
		}
		if rootKey, err = pemutil.Read(key); err != nil {
			return err
		}
	case ra != "" && ra != apiv1.CloudCAS:
		return errs.InvalidFlagValue(ctx, "ra", ctx.String("ra"), "CloudCAS")
	}

	configure := !ctx.Bool("pki")
	noDB := ctx.Bool("no-db")
	if !configure && noDB {
		return errs.IncompatibleFlagWithFlag(ctx, "pki", "no-db")
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

	var name, org, resource string
	var casOptions apiv1.Options
	switch ra {
	case apiv1.CloudCAS:
		var create bool
		var project, location string

		iss := ctx.String("issuer")
		if iss == "" {
			create, err = ui.PromptYesNo("Would you like to create a new PKI (y) or use an existing one (n)?")
			if err != nil {
				return err
			}
			if create {
				name, err = ui.Prompt("What would you like to name your new PKI? (e.g. Smallstep)",
					ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("name")))
				if err != nil {
					return err
				}
				org, err = ui.Prompt("What is the name of your your organization? (e.g. Smallstep)",
					ui.WithValidateNotEmpty())
				if err != nil {
					return err
				}
				resource, err = ui.Prompt("What resource id do you want to use? [we will append -Root-CA or -Intermediate-CA] (e.g. Smallstep)",
					ui.WithValidateRegexp("^[a-zA-Z0-9-_]+$"))
				if err != nil {
					return err
				}
				project, err = ui.Prompt("What is the id of your project on Google's Cloud Platform? (e.g. smallstep-ca)",
					ui.WithValidateRegexp("^[a-z][a-z0-9-]{4,28}[a-z0-9]$"))
				if err != nil {
					return err
				}
				location, err = ui.Prompt("What region or location do you want to use? (e.g. us-west1)",
					ui.WithValidateRegexp("^[a-z0-9-]+$"))
				if err != nil {
					return err
				}
			} else {
				iss, err = ui.Prompt("What certificate authority would you like to use? (e.g. projects/smallstep-ca/locations/us-west1/certificateAuthorities/intermediate-ca)",
					ui.WithValidateRegexp("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/certificateAuthorities/[a-zA-Z0-9-_]+$"))
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
		}
	default:
		name, err = ui.Prompt("What would you like to name your new PKI? (e.g. Smallstep)",
			ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("name")))
		if err != nil {
			return err
		}
		org = name
		casOptions = apiv1.Options{
			Type:      apiv1.SoftCAS,
			IsCreator: true,
		}
	}

	p, err := pki.New(casOptions)
	if err != nil {
		return err
	}

	if configure {
		var names string
		names, err = ui.Prompt("What DNS names or IP addresses would you like to add to your new CA? (e.g. ca.smallstep.com[,1.1.1.1,etc.])",
			ui.WithValidateFunc(ui.DNS()), ui.WithValue(ctx.String("dns")))
		if err != nil {
			return err
		}
		names = strings.Replace(names, " ", ",", -1)
		parts := strings.Split(names, ",")
		var dnsNames []string
		for _, name := range parts {
			if len(name) == 0 {
				continue
			}
			dnsNames = append(dnsNames, strings.TrimSpace(name))
		}

		var address string
		address, err = ui.Prompt("What address will your new CA listen at? (e.g. :443)",
			ui.WithValidateFunc(ui.Address()), ui.WithValue(ctx.String("address")))
		if err != nil {
			return err
		}

		var provisioner string
		provisioner, err = ui.Prompt("What would you like to name the first provisioner for your new CA? (e.g. you@smallstep.com)",
			ui.WithValidateNotEmpty(), ui.WithValue(ctx.String("provisioner")))
		if err != nil {
			return err
		}

		p.SetProvisioner(provisioner)
		p.SetAddress(address)
		p.SetDNSNames(dnsNames)
		p.SetCAURL(caURL)
	}

	pass, err := ui.PromptPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]",
		ui.WithRichPrompt(), ui.WithValue(password))
	if err != nil {
		return err
	}

	if configure {
		// Generate provisioner key pairs.
		if len(provisionerPassword) > 0 {
			if err = p.GenerateKeyPairs(provisionerPassword); err != nil {
				return err
			}
		} else {
			if err = p.GenerateKeyPairs(pass); err != nil {
				return err
			}
		}
	}

	if casOptions.IsCreator {
		var root *apiv1.CreateCertificateAuthorityResponse
		// Generate root certificate if not set.
		if rootCrt == nil && rootKey == nil {
			fmt.Println()
			fmt.Print("Generating root certificate... \n")

			root, err = p.GenerateRootCertificate(name, org, resource, pass)
			if err != nil {
				return err
			}

			fmt.Println("all done!")
		} else {
			fmt.Println()
			fmt.Print("Copying root certificate... \n")
			// Do not copy key in STEPPATH
			if err = p.WriteRootCertificate(rootCrt, nil, nil); err != nil {
				return err
			}
			root = p.CreateCertificateAuthorityResponse(rootCrt, rootKey)
			fmt.Println("all done!")
		}

		fmt.Println()
		fmt.Print("Generating intermediate certificate... \n")

		err = p.GenerateIntermediateCertificate(name, org, resource, root, pass)
		if err != nil {
			return err
		}
	} else {
		// Attempt to get the root certificate from RA.
		if err := p.GetCertificateAuthority(); err != nil {
			return err
		}
	}

	if ctx.Bool("ssh") {
		fmt.Println()
		fmt.Print("Generating user and host SSH certificate signing keys... \n")
		if err := p.GenerateSSHSigningKeys(pass); err != nil {
			return err
		}
	}

	fmt.Println("all done!")

	if !configure {
		p.TellPKI()
		return nil
	}
	opts := []pki.Option{}
	if noDB {
		opts = append(opts, pki.WithoutDB())
	}
	return p.Save(opts...)
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
