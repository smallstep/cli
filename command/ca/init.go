package ca

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
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
	}
}

func initAction(ctx *cli.Context) error {
	if err := assertCryptoRand(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "What would you like to name your new PKI? (e.g. Smallstep): ")
	name, err := utils.ReadString(os.Stdin)
	if err != nil {
		return err
	}

	pass, err := utils.ReadPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]: ")
	if err != nil {
		return err
	}

	p, err := pki.New(pki.GetPublicPath(), pki.GetSecretsPath(), pki.GetConfigPath())
	if err != nil {
		return err
	}

	// Generate ott and ssh key pairs
	if err := p.GenerateKeyPairs(pass); err != nil {
		return err
	}

	fmt.Println()
	fmt.Print("Generating root certificate... \n")

	rootCrt, rootKey, err := p.GenerateRootCertificate(name+" Root CA", pass)
	if err != nil {
		return err
	}

	fmt.Println("all done!")

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
