package actions

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// Command returns the principal policy subcommand.
func PrincipalsCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "principal")
	return cli.Command{
		Name:  "principal",
		Usage: "add or remove principals",
		UsageText: fmt.Sprintf(`**%s** <principal> [**--remove**]
[**--provisioner**=<name>] [**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages principals in SSH policies
		
## EXAMPLES	

Allow all principals in SSH host certificates on authority level
'''
$ step ca policy authority ssh host allow principal "*"
'''

Allow all principals in SSH user certificates on authority level
'''
$ step ca policy authority ssh user allow principal "*"
'''

Allow principal machine-name in SSH host certificates on provisioner level
'''
$ step ca policy provisioner ssh host allow principal machine-name --provisioner my_ssh_host_provisioner
'''

Allow principal user in SSH user certificates on provisioner level
'''
$ step ca policy provisioner ssh host allow principal user --provisioner my_ssh_user_provisioner
'''

Deny principal root in SSH user certificates on provisioner level
'''
$ step ca policy provisioner ssh host deny principal root --provisioner my_ssh_user_provisioner
'''

`, commandName),
		Action: command.InjectContext(
			ctx,
			principalAction,
		),
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided Principals from the policy instead of adding them`,
			},
		},
	}
}

func principalAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)

	args := clictx.Args()
	if len(args) == 0 {
		return errors.New("please provide at least one principal")
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return err
	}

	var principals []string

	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			principals = policy.Ssh.Host.Allow.Principals
		case policycontext.IsDeny(ctx):
			principals = policy.Ssh.Host.Deny.Principals
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			principals = policy.Ssh.User.Allow.Principals
		case policycontext.IsDeny(ctx):
			principals = policy.Ssh.User.Deny.Principals
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsX509Policy(ctx):
		return errors.New("X.509 policy does not support principals")
	default:
		panic("no SSH nor X.509 context set")
	}

	if clictx.Bool("remove") {
		for _, domain := range args {
			principals = remove(domain, principals)
		}
	} else {
		principals = append(principals, args...)
	}

	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.Host.Allow.Principals = principals
		case policycontext.IsDeny(ctx):
			policy.Ssh.Host.Deny.Principals = principals
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.User.Allow.Principals = principals
		case policycontext.IsDeny(ctx):
			policy.Ssh.User.Deny.Principals = principals
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsX509Policy(ctx):
		return errors.New("X.509 policy does not support principals")
	default:
		panic("no SSH nor X.509 context set")
	}

	updatedPolicy, err := updatePolicy(ctx, client, policy)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	return prettyPrint(updatedPolicy)
}
