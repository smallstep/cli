package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/linkedca"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// ViewCommand returns the policy view subcommand
func ViewCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "view")
	return cli.Command{
		Name:  "view",
		Usage: "view current certificate issuance policy",
		UsageText: fmt.Sprintf(`**%s**
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** shows the currently configured policy.

## EXAMPLES

View the authority certificate issuance policy
'''
$ step ca policy authority view
'''

View a provisioner certificate issuance policy
'''
$ step ca policy provisioner view --provisioner my_provisioner
'''

View an ACME EAB certificate issuance policy by reference
'''
$ step ca policy acme view --provisioner my_acme_provisioner --eab-key-reference my_reference
'''

View an ACME EAB certificate issuance policy by EAB Key ID
'''
$ step ca policy acme view --provisioner my_acme_provisioner --eab-key-id "lUOTGwvFQADjk8nxsVufbhyTOwrFmvO2"
'''`, commandName),
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
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func viewAction(ctx context.Context) (err error) {
	clictx := command.CLIContextFromContext(ctx)
	provisioner := clictx.String("provisioner")
	reference := clictx.String("eab-key-reference")
	keyID := clictx.String("eab-key-id")

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	var (
		policy *linkedca.Policy
	)

	switch {
	case policycontext.IsAuthorityPolicyLevel(ctx):
		policy, err = client.GetAuthorityPolicy()
	case policycontext.IsProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		policy, err = client.GetProvisionerPolicy(provisioner)
	case policycontext.IsACMEPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return errs.RequiredOrFlag(clictx, "eab-key-reference", "eab-key-id")
		}
		policy, err = client.GetACMEPolicy(provisioner, reference, keyID)
	default:
		panic("no context for policy retrieval set")
	}

	if err != nil {
		var ae *ca.AdminClientError
		if errors.As(err, &ae) && ae.Type == "notFound" { // TODO: use constant?
			fmt.Println("certificate issuance policy does not exist")
			return nil
		}

		return fmt.Errorf("error retrieving authority policy: %w", err)
	}

	prettyPrint(policy)

	return nil
}
