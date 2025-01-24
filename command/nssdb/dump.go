package nssdb

import (
	"context"
	"errors"
	"strconv"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/step-agent-plugin/pkg/nssdb"
)

func dumpCommand() cli.Command {
	return cli.Command{
		Name:      "dump",
		Action:    cli.ActionFunc(dumpAction),
		Usage:     `dump an object in an NSS database`,
		UsageText: `**step nssdb dump** <id>`,
		Description: `**step nssdb dump** prints the raw record of an object in an NSS database.
This is for advanced debugging only.

## POSITIONAL ARGUMENTS

<id>
:  ID of a record in the cert or key database.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

'''
$ step nssdb dump 272362910
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "dir",
				Value: "text",
				Usage: `The directory that holds the NSS database.`,
			},
		},
	}
}

func dumpAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 1, 1); err != nil {
		return err
	}

	var (
		idArg = ctx.Args().Get(0)
		dir   = ctx.String("dir")
	)

	id, err := strconv.Atoi(idArg)
	if err != nil {
		return errors.New("id must be an integer")
	}

	db, err := nssdb.New(dir)
	if err != nil {
		return err
	}
	defer db.Close()

	obj, err := db.QueryCertificateRow(context.Background(), id)
	if err != nil {
		return err
	}

	obj.Print()

	return nil
}
