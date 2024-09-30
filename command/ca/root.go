package ca

import (
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
)

func rootCommand() cli.Command {
	return cli.Command{
		Name:   "root",
		Action: command.ActionFunc(rootAction),
		Usage:  "download and validate the root certificate",
		UsageText: `**step ca root** [<root-file>]
[**--ca-url**=<uri>] [**--fingerprint**=<fingerprint>] [**--context**=<name>]`,
		Description: `**step ca root** downloads and validates the root certificate from the
certificate authority.

## POSITIONAL ARGUMENTS

<root-file>
:  File to write root certificate (PEM format)

## EXAMPLES

Get the root fingerprint in the CA:
'''
$ step certificate fingerprint /path/to/root_ca.crt
0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Download the root certificate from the configured certificate authority:
'''
$ step ca root root_ca.crt \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Download the root certificate using a given certificate authority:
'''
$ step ca root root_ca.crt \
  --ca-url https://ca.smallstep.com:9000 \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Print the root certificate using the flags set by <step ca bootstrap>:
'''
$ step ca root
'''`,
		Flags: []cli.Flag{
			flags.Force,
			fingerprintFlag,
			flags.CaURL,
			flags.Context,
		},
	}
}

func rootAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
	}

	fingerprint := strings.TrimSpace(ctx.String("fingerprint"))
	if fingerprint == "" {
		return errs.RequiredFlag(ctx, "fingerprint")
	}

	client, err := ca.NewClient(caURL, ca.WithInsecure())
	if err != nil {
		return err
	}

	// Root already validates the certificate
	resp, err := client.Root(fingerprint)
	if err != nil {
		return errors.Wrap(err, "error downloading root certificate")
	}

	if rootFile := ctx.Args().Get(0); rootFile != "" {
		if _, err := pemutil.Serialize(resp.RootPEM.Certificate, pemutil.ToFile(rootFile, 0600)); err != nil {
			return err
		}
		ui.Printf("The root certificate has been saved in %s.\n", rootFile)
	} else {
		block, err := pemutil.Serialize(resp.RootPEM.Certificate)
		if err != nil {
			return err
		}
		fmt.Print(string(pem.EncodeToMemory(block)))
	}
	return nil
}
