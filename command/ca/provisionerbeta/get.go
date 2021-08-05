package provisionerbeta

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"google.golang.org/protobuf/encoding/protojson"
)

func getCommand() cli.Command {
	return cli.Command{
		Name:   "get",
		Action: cli.ActionFunc(getAction),
		Usage:  "get a provisioner from the CA configuration",
		UsageText: `**step beta ca provisioner get** <name>
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<context>]`,
		Flags: []cli.Flag{
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
		Description: `**step beta ca provisioner get** gets a provisioner from the CA configuration.

## EXAMPLES

Get a provisioner by name:
'''
$ step beta ca provisioner get acme
'''
`,
	}
}

func getAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args.Get(0)

	// Create online client
	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	p, err := client.GetProvisioner(ca.WithProvisionerName(name))
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	b, err := protojson.Marshal(p)
	if err != nil {
		return err
	}
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return err
	}
	fmt.Println(buf.String())

	return nil
}
