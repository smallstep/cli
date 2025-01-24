package nssdb

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/step-agent-plugin/pkg/nssdb"
)

func listCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    cli.ActionFunc(listAction),
		Usage:     `list objects in an NSS database`,
		UsageText: `**step nssdb list**`,
		Description: `**step nssdb list** lists certificates and keys in an NSS database.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

'''
$ step nssdb list
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

func listAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	dir := ctx.String("dir")

	db, err := nssdb.New(dir)
	if err != nil {
		return err
	}
	defer db.Close()

	objs, err := db.ListCertDBObjects(context.Background())
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	fmt.Fprintln(w, "ID\tTYPE\tNAME")
	for _, obj := range objs {
		var class string
		switch obj.ULongAttributes["CKA_CLASS"] {
		case nssdb.CKO_CERTIFICATE:
			class = "certificate"
		case nssdb.CKO_PUBLIC_KEY:
			class = "public-key"
		case nssdb.CKO_PRIVATE_KEY:
			class = "private-key"
		case nssdb.CKO_SECRET_KEY:
			class = "secret-key"
		}

		label := obj.Attributes["CKA_LABEL"]

		if obj.ID == 0 {
			obj.Print()
		}
		fmt.Fprintf(w, "%d\t%s\t%s\n", obj.ID, class, label)
	}
	w.Flush()
	return nil
}
