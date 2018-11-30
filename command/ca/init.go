package ca

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/smallstep/cli/crypto/pemutil"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	stepx509 "github.com/smallstep/cli/pkg/x509"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
)

func initCommand() cli.Command {
	return cli.Command{
		Name:   "init",
		Action: cli.ActionFunc(initAction),
		Usage:  "initialize the CA PKI",
		UsageText: `**step ca init**
		[**--root**=<file>] [**--key**=<file>] [**--pki**]`,
		Description: `**step ca init** command initializes a public key infrastructure (PKI) to be
 used by the Certificate Authority`,
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
				Usage: "Generate only the PKI without the CA configuration",
			},
		},
	}
}

func initAction(ctx *cli.Context) error {
	if err := assertCryptoRand(); err != nil {
		return err
	}

	var rootCrt *stepx509.Certificate
	var rootKey interface{}

	root := ctx.String("root")
	key := ctx.String("key")
	configure := !ctx.Bool("pki")
	switch {
	case len(root) > 0 && len(key) == 0:
		return errs.RequiredWithFlag(ctx, "root", "key")
	case len(root) == 0 && len(key) > 0:
		return errs.RequiredWithFlag(ctx, "key", "root")
	case len(root) > 0 && len(key) > 0:
		var err error
		if rootCrt, err = pemutil.ReadStepCertificate(root); err != nil {
			return err
		}
		if rootKey, err = pemutil.Read(key); err != nil {
			return err
		}
	}

	p, err := pki.New(pki.GetPublicPath(), pki.GetSecretsPath(), pki.GetConfigPath())
	if err != nil {
		return err
	}

	name, err := ui.Prompt("What would you like to name your new PKI? (e.g. Smallstep)", ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}

	if configure {
		names, err := ui.Prompt("What DNS names or IP addresses would you like to add to your new CA? (e.g. ca.smallstep.com[,1.1.1.1,etc.])", ui.WithValidateFunc(ui.DNS()))
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

		address, err := ui.Prompt("What address will your new CA listen at? (e.g. :443)", ui.WithValidateFunc(ui.Address()))
		if err != nil {
			return err
		}

		provisioner, err := ui.Prompt("What would you like to name the first provisioner for your new CA? (e.g. you@smallstep.com)", ui.WithValidateNotEmpty())
		if err != nil {
			return err
		}

		p.SetProvisioner(provisioner)
		p.SetAddress(address)
		p.SetDNSNames(dnsNames)
	}

	pass, err := ui.PromptPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]", ui.WithRichPrompt())
	if err != nil {
		return err
	}

	if configure {
		// Generate ott key pairs.
		if err := p.GenerateKeyPairs(pass); err != nil {
			return err
		}
	}

	// Generate root certificate if not set.
	if rootCrt == nil && rootKey == nil {
		fmt.Println()
		fmt.Print("Generating root certificate... \n")

		rootCrt, rootKey, err = p.GenerateRootCertificate(name+" Root CA", pass)
		if err != nil {
			return err
		}

		fmt.Println("all done!")
	} else {
		fmt.Println()
		fmt.Print("Copying root certificate... \n")
		if err := p.WriteRootCertificate(rootCrt, rootKey, pass); err != nil {
			return err
		}
		fmt.Println("all done!")
	}

	fmt.Println()
	fmt.Print("Generating intermediate certificate... \n")

	err = p.GenerateIntermediateCertificate(name+" Intermediate CA", rootCrt, rootKey, pass)
	if err != nil {
		return err
	}

	fmt.Println("all done!")

	if !configure {
		p.TellPKI()
		return nil
	}
	return p.Save()
}

// assertCrytoRand asserts that a cryptographically secure random number
// generator is available, it will return an error otherwise.
func assertCryptoRand() error {
	buf := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return errs.NewError("crypto/rand is unavailable: Read() failed with %#v", err)
	}
	return nil
}
