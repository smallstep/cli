package provisioner

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
)

// Command returns the provisioner policy subcommand.
func viewCommand() cli.Command {
	return cli.Command{
		Name:  "view",
		Usage: "view provisioner certificate issuance policy",
		UsageText: `**step beta ca policy provisioner view** <provisioner>
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step beta ca policy provisioner view** shows the provisioner policy.`,
		Action:      cli.ActionFunc(viewAction),
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
	}
}

func viewAction(ctx *cli.Context) (err error) {

	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	provisioner := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := client.GetProvisionerPolicy(provisioner)
	if err != nil {
		var ae = new(ca.AdminClientError)
		if errors.As(err, &ae) && ae.Type == "notFound" { // TODO: use constant?
			fmt.Println("provisioner does not have a certificate issuance policy")
			return nil
		}

		return fmt.Errorf("error retrieving provisioner policy: %w", err)
	}

	b, err := json.MarshalIndent(policy, "", "   ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))

	return nil
}
