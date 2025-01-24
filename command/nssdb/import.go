package nssdb

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/step-agent-plugin/pkg/nssdb"
	"go.step.sm/crypto/pemutil"
)

func importCommand() cli.Command {
	return cli.Command{
		Name:      "import",
		Action:    cli.ActionFunc(importAction),
		Usage:     `import a certificate into an NSS database`,
		UsageText: `**step certificate import** <crt-file>`,
		Description: `**step nssdb import** adds a certificate to an NSS database.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate or certificate signing request (CSR) to inspect. A hyphen ("-") indicates STDIN as <crt-file>.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Import a local certificate (default to text format):
'''
$ step certificate import ./certificate.crt
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "dir",
				Value: "text",
				Usage: `The directory that holds the NSS database.`,
			},
			cli.StringFlag{
				Name:  "name",
				Value: "text",
				Usage: `The nickname of the certificate.`,
			},
		},
	}
}

func importAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 1, 1); err != nil {
		return err
	}

	var (
		crtFile = ctx.Args().Get(0)
		dir     = ctx.String("dir")
		name    = ctx.String("name")
	)

	crt, err := pemutil.ReadCertificate(crtFile)
	if err != nil {
		return nil
	}

	db, err := nssdb.New(dir)
	if err != nil {
		return err
	}

	return db.AddCertificate(context.Background(), crt, name)
}
