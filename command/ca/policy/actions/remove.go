package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// RemoveCommand returns the policy remove subcommand.
func RemoveCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "remove")
	return cli.Command{
		Name:  "remove",
		Usage: "remove certificate issuance policy",
		UsageText: fmt.Sprintf(`**%s** 
[**--provisioner**=<name>] [**--eab-key-id**=<eab-ey-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** removes a certificate issuance policy.

## EXAMPLES

Remove the authority certificate issuance policy
'''
$ step ca policy authority remove
'''

Remove a provisioner certificate issuance policy
'''
$ step ca policy provisioner remove --provisioner my_provisioner
'''

Remove an ACME EAB certificate issuance policy by reference
'''
$ step ca policy acme remove --provisioner my_acme_provisioner --eab-key-reference my_reference
'''

Remove an ACME EAB certificate issuance policy by EAB Key ID
'''
$ step ca policy acme remove --provisioner my_acme_provisioner --eab-key-id "lUOTGwvFQADjk8nxsVufbhyTOwrFmvO2"
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			removeAction,
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

func removeAction(ctx context.Context) (err error) {
	clictx := command.CLIContextFromContext(ctx)
	provisioner := clictx.String("provisioner")
	reference := clictx.String("eab-key-reference")
	keyID := clictx.String("eab-key-id")

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	switch {
	case policycontext.IsAuthorityPolicyLevel(ctx):
		err = client.RemoveAuthorityPolicy()
	case policycontext.IsProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		err = client.RemoveProvisionerPolicy(provisioner)
	case policycontext.IsACMEPolicyLevel(ctx):
		if provisioner == "" {
			return errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return errs.RequiredOrFlag(clictx, "eab-key-reference", "eab-key-id")
		}
		err = client.RemoveACMEPolicy(provisioner, reference, keyID)
	default:
		panic("no context for policy retrieval set")
	}

	if err != nil {
		var ae *ca.AdminClientError
		if errors.As(err, &ae) && ae.Type == "notFound" {
			return errors.New("certificate issuance policy does not exist")
		}
		return fmt.Errorf("error deleting certificate issuance policy: %w", err)
	}

	fmt.Println("policy deleted")

	return nil
}
