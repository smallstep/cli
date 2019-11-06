package ca

import (
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

type flowType int

const (
	rootsFlow flowType = iota
	federationFlow
)

func rootsCommand() cli.Command {
	return cli.Command{
		Name:   "roots",
		Action: command.ActionFunc(rootsAction),
		Usage:  "download all the root certificates",
		UsageText: `**step ca roots** <roots-file>
		[**--ca-url**=<uri>] [**--root**=<file>]`,
		Description: `**step ca roots** downloads a certificate bundle with all the root
certificates.

## POSITIONAL ARGUMENTS

<roots-file>
:  File to write all the root certificates (PEM format)

## EXAMPLES

Download the roots with flags set by <step ca bootstrap>:
'''
$ step ca roots roots.pem
'''

Download the roots with custom flags:
'''
$ step ca roots roots.pem \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Force,
			flags.Root,
		},
	}
}

func federationCommand() cli.Command {
	return cli.Command{
		Name:   "federation",
		Action: command.ActionFunc(federationAction),
		Usage:  "download all the federated certificates",
		UsageText: `**step ca federation** <federation-file>
		[**--ca-url**=<uri>] [**--root**=<file>]`,
		Description: `**step ca federation** downloads a certificate bundle with all the root
certificates in the federation.

## POSITIONAL ARGUMENTS

<federation-file>
:  File to write federation certificates (PEM format)

## EXAMPLES

Download the federated roots with flags set by <step ca bootstrap>:
'''
$ step ca federation federation.pem
'''

Download the federated roots with custom flags:
'''
$ step ca federation federation.pem \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt
'''
`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Force,
			flags.Root,
		},
	}
}

func rootsAction(ctx *cli.Context) error {
	return rootsAndFederationFlow(ctx, rootsFlow)
}

func federationAction(ctx *cli.Context) error {
	return rootsAndFederationFlow(ctx, federationFlow)
}

func rootsAndFederationFlow(ctx *cli.Context, typ flowType) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	client, err := ca.NewClient(caURL, ca.WithRootFile(root))
	if err != nil {
		return err
	}

	var certs []api.Certificate
	switch typ {
	case rootsFlow:
		roots, err := client.Roots()
		if err != nil {
			return err
		}
		certs = roots.Certificates
	case federationFlow:
		federation, err := client.Federation()
		if err != nil {
			return err
		}
		certs = federation.Certificates
	default:
		return errors.New("unknown flow type: this should not happen")
	}

	var data []byte
	for _, cert := range certs {
		block, err := pemutil.Serialize(cert.Certificate)
		if err != nil {
			return err
		}
		data = append(data, pem.EncodeToMemory(block)...)
	}

	outFile := ctx.Args().Get(0)
	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return err
	}

	switch typ {
	case rootsFlow:
		ui.Printf("The root certificate bundle has been saved in %s.\n", outFile)
	case federationFlow:
		ui.Printf("The federation certificate bundle has been saved in %s.\n", outFile)
	default:
		return errors.New("unknown flow type: this should not happen")
	}

	return nil
}
