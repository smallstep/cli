package certificates

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	stepx509 "github.com/smallstep/cli/crypto/certificates/x509"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils/reader"
	"github.com/urfave/cli"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:      "sign",
		Action:    cli.ActionFunc(signAction),
		Usage:     "sign a certificate signing request (CSR).",
		UsageText: `step certificates sign CSR_FILE CRT_FILE KEY_FILE [--token=TOKEN]`,
		Description: `The 'step certificates sign' generates a signed certificate from a
  certificate signing requests (CSR).

  POSITIONAL ARGUMENTS
    CSR_FILE
      The path to a certificate signing request (CSR) to be signed.
    CRT_FILE
      The path to an issuing certificate.
    KEY_FILE
      The path to a private key for signing the CSR.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "token",
				Usage: `A provisioning token or bootstrap token for secure introduction and
  mutual authentication with an unknown CA.`,
			},
		},
	}
}

func signAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	csrFile := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)

	// Load the CSR into an x509 Certificate Template.
	csrBytes, err := ioutil.ReadFile(csrFile)
	if err != nil {
		return errors.WithStack(err)
	}
	csr, err := stepx509.LoadCSRFromBytes(csrBytes)
	if err != nil {
		return errors.WithStack(err)
	}
	// Load the Issuer Certificate.
	issuerCrt, _, err := stepx509.LoadCertificate(crtFile)
	if err != nil {
		return errors.WithStack(err)
	}

	// Load the Issuer Private Key.
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errors.WithStack(err)
	}
	key, err := keys.LoadPrivateKey(keyBytes, func() (string, error) {
		var pass string
		if err := reader.ReadPasswordSubtle(
			fmt.Sprintf("Password with which to decrypt private key %s: ", keyFile),
			&pass, "Password", reader.RetryOnEmpty); err != nil {
			return "", err
		}
		return pass, nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	leafProfile, err := stepx509.NewLeafProfileWithCSR(csr, issuerCrt, key)
	if err != nil {
		return errors.WithStack(err)
	}

	crtBytes, err := leafProfile.CreateCertificate()
	if err != nil {
		return errors.Wrapf(err, "failure creating new leaf certificate from input csr")
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}
	fmt.Printf("%s", string(pem.EncodeToMemory(block)))

	//tok := ctx.String("token")
	return nil
}
