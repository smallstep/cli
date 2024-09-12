package certificate

import (
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func bundleCommand() cli.Command {
	return cli.Command{
		Name:      "bundle",
		Action:    command.ActionFunc(bundleAction),
		Usage:     `bundle a certificate with intermediate certificate(s) needed for certificate path validation`,
		UsageText: `**step certificate bundle** <crt-file> <ca> <bundle-file>`,
		Description: `**step certificate bundle** bundles a certificate
		with any intermediates necessary to validate the certificate.

## POSITIONAL ARGUMENTS

<crt-file>
: The path to a leaf certificate to bundle with issuing certificate(s).

<ca>
: The path to the Certificate Authority issuing certificate.

<bundle-file>
: The path to write the bundle.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Bundle a certificate with the intermediate certificate authority (issuer):

'''
$ step certificate bundle foo.crt intermediate-ca.crt foo-bundle.crt
'''
`,
		Flags: []cli.Flag{flags.Force},
	}
}

func bundleAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	crtFile := ctx.Args().Get(0)
	crtBytes, err := os.ReadFile(crtFile)
	if err != nil {
		return errs.FileError(err, crtFile)
	}
	crtBlock, _ := pem.Decode(crtBytes)
	if crtBlock == nil {
		return errors.Errorf("could not parse certificate file '%s'", crtFile)
	}

	caFile := ctx.Args().Get(1)
	caBytes, err := os.ReadFile(caFile)
	if err != nil {
		return errs.FileError(err, caFile)
	}
	caBlock, _ := pem.Decode(caBytes)
	if caBlock == nil {
		return errors.Errorf("could not parse certificate file '%s'", caFile)
	}

	chainFile := ctx.Args().Get(2)
	if err := utils.WriteFile(chainFile,
		append(pem.EncodeToMemory(crtBlock), pem.EncodeToMemory(caBlock)...), 0600); err != nil {
		return err
	}

	ui.Printf("Your certificate has been saved in %s.\n", chainFile)
	return nil
}
