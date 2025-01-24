package nssdb

import (
	"context"
	"errors"
	"strconv"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"go.step.sm/crypto/nssdb"
)

func rawCommand() cli.Command {
	return cli.Command{
		Name:      "raw",
		Action:    cli.ActionFunc(rawAction),
		Usage:     `raw an object in an NSS database`,
		UsageText: `**step nssdb raw** <id>`,
		Description: `**step nssdb raw** prints the raw record of an object in an NSS database.
This is for advanced debugging only.

## POSITIONAL ARGUMENTS

<id>
:  ID of a record in the cert or key database.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

'''
$ step nssdb raw 272362910
'''
`,
		Flags: []cli.Flag{
			flags.NSSDir,
			flags.PasswordFile,
		},
	}
}

func rawAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 1, 1); err != nil {
		return err
	}

	var (
		idArg  = ctx.Args().Get(0)
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

	id, err := strconv.Atoi(idArg)
	if err != nil {
		return errors.New("id must be an integer")
	}

	db, err := nssdb.New(dir, password)
	if err != nil {
		return err
	}
	defer db.Close()

	obj, err := db.GetObject(context.Background(), uint32(id))
	if err != nil {
		return err
	}

	obj.Print()

	return nil
}
