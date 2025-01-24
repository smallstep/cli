package nssdb

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"go.step.sm/crypto/nssdb"
	"go.step.sm/crypto/pemutil"
)

func importCommand() cli.Command {
	return cli.Command{
		Name:      "import",
		Action:    cli.ActionFunc(importAction),
		Usage:     `import a certificate into an NSS database`,
		UsageText: `**step certificate import** <crt-file> <key-file>`,
		Description: `**step nssdb import** adds a certificate to an NSS database.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate to import.

<key-file>
:  Path to a private key for the certificate to inspect.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Import a local certificate (default to text format):
'''
$ step certificate import ./certificate.crt
'''
`,
		Flags: []cli.Flag{
			flags.NSSDir,
			flags.PasswordFile,
			cli.StringFlag{
				Name:  "name",
				Value: "text",
				Usage: `The nickname of the certificate.`,
			},
		},
	}
}

func importAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 2, 2); err != nil {
		return err
	}

	var (
		crtFile = ctx.Args().Get(0)
		keyFile = ctx.Args().Get(1)
		dir     = ctx.String("dir")
		pwFile  = ctx.String("password-file")
		name    = ctx.String("name")
	)

	crt, err := pemutil.ReadCertificate(crtFile)
	if err != nil {
		return err
	}

	key, err := pemutil.Read(keyFile)
	if err != nil {
		return err
	}

	var password []byte
	if pwFile != "" {
		pw, err := utils.ReadPasswordFromFile(pwFile)
		if err != nil {
			return err
		}
		password = pw
	}

	db, err := nssdb.New(dir, password)
	if err != nil {
		return err
	}

	_, _, _, err = db.Import(context.Background(), name, crt, key)
	return err
}
