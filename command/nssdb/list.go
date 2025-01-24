package nssdb

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"go.step.sm/crypto/nssdb"
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
			flags.NSSDir,
			flags.PasswordFile,
		},
	}
}

func listAction(ctx *cli.Context) error {
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

	objs, err := db.ListObjects(context.Background())
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 1, '\t', 0)

	certs := map[string]*nssdb.Object{}
	pubKeys := map[string]*nssdb.Object{}
	privKeys := map[string]*nssdb.Object{}

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
		ckaID, ok := obj.Attributes["CKA_ID"]
		if ok {
			id := string(ckaID)
			switch class {
			case "certificate":
				certs[id] = obj
			case "public-key":
				pubKeys[id] = obj
			case "private-key":
				privKeys[id] = obj
			}
			continue
		}
		label := obj.Attributes["CKA_LABEL"]
		fmt.Fprintf(w, "%d\t%s\t%s\n", obj.ID, class, label)
	}

	for subjKeyID, certObj := range certs {
		fmt.Fprintf(w, "%d\t%s\t%s\n", certObj.ID, "certificate", certObj.Attributes["CKA_LABEL"])

		pubKey, ok := pubKeys[subjKeyID]
		if ok {
			fmt.Fprintf(w, "%d\t%s\t%s\n", pubKey.ID, "-> public-key", "")
			delete(pubKeys, subjKeyID)
		}
		privKey, ok := privKeys[subjKeyID]
		if ok {
			fmt.Fprintf(w, "%d\t%s\t%s\n", privKey.ID, "-> private-key", "")
			delete(privKeys, subjKeyID)
		}
	}

	w.Flush()
	return nil
}
