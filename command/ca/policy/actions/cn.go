package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// CommonNamesCommand returns the common names policy subcommand.
func CommonNamesCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "cn")
	return cli.Command{
		Name:  "cn",
		Usage: "add or remove common names",
		UsageText: fmt.Sprintf(`**%s** <name> [**--remove**]
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages common names in policies

## EXAMPLES

Allow "My CA Name" as Common Name in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow cn "My CA Name"
'''

Allow www.example.com as Common Name in X.509 certificates on authority level.
This can be used in case www.example.com is not allowed as a DNS SAN, but is
allowed to be used in the Common Name.
'''
$ step ca policy authority x509 allow cn www.example.com
'''

Remove www.example.com from allowed Common Names in X.509 certificates on authority level.
'''
$ step ca policy authority x509 allow cn www.example.com --remove
'''

Deny "My Bad CA Name" as Common Name in X.509 certificates on authority level
'''
$ step ca policy authority x509 deny cn "My Bad CA Name"
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			commonNamesAction,
		),
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.EABKeyID,
			flags.EABReference,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided Common Names from the policy instead of adding them`,
			},
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

func commonNamesAction(ctx context.Context) (err error) {
	clictx := command.CLIContextFromContext(ctx)

	args := clictx.Args()
	if len(args) == 0 {
		return errs.TooFewArguments(clictx)
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return fmt.Errorf("error retrieving policy: %w", err)
	}

	shouldRemove := clictx.Bool("remove")

	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support Common Names")
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support Common Names")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.CommonNames = addOrRemoveArguments(policy.X509.Allow.CommonNames, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.CommonNames = addOrRemoveArguments(policy.X509.Deny.CommonNames, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	updatedPolicy, err := updatePolicy(ctx, client, policy)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	return prettyPrint(updatedPolicy)
}
