package provisioner

import (
	"fmt"

	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func update2Command() cli.Command {
	return cli.Command{
		Name:      "update2",
		Action:    cli.ActionFunc(update2Action),
		Usage:     "update a provisioner in the CA configuration",
		UsageText: `**step ca provisioner update** [**--ca-url**=<uri>] [**--root**=<file>]`,
		Flags: []cli.Flag{
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner update** updates a provisioners in the CA configuration.

## EXAMPLES

update all provisioners:
'''
$ step ca provisioner update
'''
`,
	}
}

func update2Action(ctx *cli.Context) (err error) {
	fmt.Println("not implemented\n")
	/*
		if err := errs.NumberOfArguments(ctx, 0); err != nil {
			return err
		}

		caURL, err := flags.ParseCaURLIfExists(ctx)
		if err != nil {
			return err
		}
		if len(caURL) == 0 {
			return errs.RequiredFlag(ctx, "ca-url")
		}
		rootFile := ctx.String("root")
		if len(rootFile) == 0 {
			rootFile = pki.GetRootCAPath()
			if _, err := os.Stat(rootFile); err != nil {
				return errs.RequiredFlag(ctx, "root")
			}
		}

		// Create online client
		var options []ca.ClientOption
		options = append(options, ca.WithRootFile(rootFile))
		client, err := ca.NewMgmtClient(caURL, options...)
		if err != nil {
			return err
		}

		provs, err := client.GetProvisioners()
		if err != nil {
			return err
		}

		b, err := json.MarshalIndent(provs, "", "   ")
		if err != nil {
			return errors.Wrap(err, "error marshaling provisioners")
		}

		fmt.Println(string(b))
	*/
	return nil
}
