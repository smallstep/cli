package provisioner

import (
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"go.step.sm/cli-utils/errs"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
)

// removeCommand returns the provisioner policy remove subcommand.
func removeCommand() cli.Command {
	return cli.Command{
		Name:  "remove",
		Usage: "remove provisioner certificate issuance policy",
		UsageText: `**step beta ca policy provisioner remove** <provisioner>
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step beta ca policy provisioner remove** removes the full certificate issuance policy from the provisioner`,
		Action:      cli.ActionFunc(removeAction),
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

func removeAction(ctx *cli.Context) (err error) {

	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	provisioner := args.Get(0)

	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	err = client.RemoveProvisionerPolicy(provisioner)
	if err != nil {
		var ae = new(ca.AdminClientError)
		if errors.As(err, &ae) && ae.Type == "notFound" {
			return errors.New("provisioner policy doesn't exist")
		}
		return fmt.Errorf("error deleting provisioner policy: %w", err)
	}

	fmt.Println("provisioner policy deleted")

	return nil
}
