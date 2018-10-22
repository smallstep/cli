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
		Name:      "init",
		Action:    cli.ActionFunc(initAction),
		Usage:     "initializes the CA PKI",
		UsageText: `**step ca init**`,
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

	name, err := ui.Prompt("What would you like to name your new PKI? (e.g. Smallstep)", ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}

	names, err := ui.Prompt("What DNS names or IP addresses would you like to add to your new CA? (e.g. ca.smallstep.com)", ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}
	names = strings.Replace(names, ",", " ", -1)
	dnsNames := strings.Split(names, " ")
	for i, name := range dnsNames {
		dnsNames[i] = strings.TrimSpace(name)
	}

	address, err := ui.Prompt("What address would your new CA will be listening at? (e.g. :443)", ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}

	issuer, err := ui.Prompt("What first issuer would like to add in the new CA? (e.g. you@smallstep.com)", ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}

	pass, err := ui.PromptPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]")
	if err != nil {
		return err
	}

	p, err := pki.New(pki.GetPublicPath(), pki.GetSecretsPath(), pki.GetConfigPath())
	if err != nil {
		return err
	}

	p.SetIssuer(issuer)
	p.SetAddress(address)
	p.SetDNSNames(dnsNames)

	// Generate ott and ssh key pairs
	if err := p.GenerateKeyPairs(pass); err != nil {
		return err
	}

	// Generate root certificate if not set
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

	if err = p.Save(); err != nil {
		return err
	}

	return nil
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
