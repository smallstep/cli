package provisionerbeta

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"
)

func getCommand() cli.Command {
	return cli.Command{
		Name:      "get",
		Action:    cli.ActionFunc(getAction),
		Usage:     "get a provisioner from the CA configuration",
		UsageText: `**step beta ca provisioner get** <name> [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.X5cCert,
			flags.X5cKey,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step beta ca provisioner get** gets a provisioner from the CA configuration.

## EXAMPLES

Get a provisioner by name:
'''
$ step beta ca provisioner get admin-jwk
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
