package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
)

// RemoveCommand returns the policy remove subcommand.
func RemoveCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:  "remove",
		Usage: "remove authority certificate issuance policy",
		UsageText: `**step beta ca policy authority remove** 
[**--provisioner**=<name>] [**--key-id**=<key-id>] [**--reference**=<reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step beta ca policy authority remove** removes the full certificate issuance policy from the authority`,
		Action: command.InjectContext(
			ctx,
			removeAction,
		),
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.KeyID,
			flags.Reference,
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

func removeAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)
	provisioner := clictx.String("provisioner")
	reference := clictx.String("reference")
	keyID := clictx.String("key-id")

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	switch {
	case policycontext.HasAuthorityPolicyLevel(ctx):
		err = client.RemoveAuthorityPolicy()
	case policycontext.HasProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		err = client.RemoveProvisionerPolicy(provisioner)
	case policycontext.HasACMEPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return errs.RequiredOrFlag(clictx, "reference", "key-id")
		}
		err = client.RemoveACMEPolicy(provisioner, reference, keyID)
	default:
		panic("no context for policy retrieval set")
	}

	if err != nil {
		var ae = new(ca.AdminClientError)
		if errors.As(err, &ae) && ae.Type == "notFound" {
			return errors.New("certificate issuance policy does not exist")
		}
		return fmt.Errorf("error deleting certificate issuance policy: %w", err)
	}

	fmt.Println("policy deleted")

	return nil
}
