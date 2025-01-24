package nssdb

import (
	"context"
	"errors"
	"strconv"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/step-agent-plugin/pkg/nssdb"
)

func deleteCommand() cli.Command {
	return cli.Command{
		Name:      "delete",
		Action:    cli.ActionFunc(deleteAction),
		Usage:     `delete an object in an NSS database`,
		UsageText: `**step nssdb delete** <id>`,
		Description: `**step nssdb delete** deletes a row in an NSS database.

## POSITIONAL ARGUMENTS

<id>
:  ID of a record in the cert or key database.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

'''
$ step nssdb delete 272362910
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

func deleteAction(ctx *cli.Context) error {
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

	err = db.DeletePublic(context.Background(), id)
	if err != nil {
		return err
	}

	return nil
}
