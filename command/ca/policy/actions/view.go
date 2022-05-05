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
	"go.step.sm/linkedca"
)

// ViewCommand returns the policy view subcommand
func ViewCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:  "view",
		Usage: "view authority certificate issuance policy",
		UsageText: `**step beta ca policy authority view**
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-reference**=<eab-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step beta ca policy authority view** shows the authority policy.`,
		Action: command.InjectContext(
			ctx,
			viewAction,
		),
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.EABKeyID,
			flags.EABReference,
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
	provisioner := clictx.String("provisioner")
	reference := clictx.String("eab-reference")
	keyID := clictx.String("eab-key-id")

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	var (
		policy *linkedca.Policy
	)

	switch {
	case policycontext.HasAuthorityPolicyLevel(ctx):
		policy, err = client.GetAuthorityPolicy()
	case policycontext.HasProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		policy, err = client.GetProvisionerPolicy(provisioner)
	case policycontext.HasACMEPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return errs.RequiredOrFlag(clictx, "eab-reference", "eab-key-id")
		}
		policy, err = client.GetACMEPolicy(provisioner, reference, keyID)
	default:
		panic("no context for policy retrieval set")
	}

	if err != nil {
		var ae = new(ca.AdminClientError)
		if errors.As(err, &ae) && ae.Type == "notFound" { // TODO: use constant?
			fmt.Println("certificate issuance policy does not exist")
			return nil
		}

		return fmt.Errorf("error retrieving authority policy: %w", err)
	}

	prettyPrint(policy)

	return nil
}
