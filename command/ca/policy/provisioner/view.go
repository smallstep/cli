package provisioner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"google.golang.org/protobuf/encoding/protojson"
)

// Command returns the provisioner policy subcommand.
func viewCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:  "view",
		Usage: "view provisioner certificate issuance policy",
		UsageText: `**step beta ca policy provisioner view** <provisioner>
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step beta ca policy provisioner view** shows the provisioner policy.`,
		Action: command.InjectContext(
			ctx,
			viewAction,
		),
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

func viewAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)

	if err := errs.NumberOfArguments(clictx, 1); err != nil {
		return err
	}

	args := clictx.Args()
	provisioner := args.Get(0)

	client, err := cautils.NewAdminClient(clictx)
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

	b, err := protojson.Marshal(policy)
	if err != nil {
		return fmt.Errorf("error marshaling policy: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "   "); err != nil {
		return fmt.Errorf("error indenting policy JSON representation: %w", err)
	}

	fmt.Println(buf.String())

	return nil
}
