package nssdb

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"go.step.sm/crypto/nssdb"
)

func resetCommand() cli.Command {
	return cli.Command{
		Name:      "reset",
		Action:    cli.ActionFunc(resetAction),
		Usage:     `remove all objects from the database`,
		UsageText: `**step nssdb reset** <id>`,
		Description: `**step nssdb reset** deletes all objects from an NSS database.
The password in the metaData table is not affected.
This is for advanced debugging onl'''
$ step nssdb reset
'''
`,
		Flags: []cli.Flag{
			flags.NSSDir,
			flags.PasswordFile,
		},
	}
}

func resetAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 0); err != nil {
		return err
	}

	var (
		dir    = ctx.String("dir")
		pwFile = ctx.String("password-file")
	)

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
	defer db.Close()

	return db.Reset(context.Background())
}
