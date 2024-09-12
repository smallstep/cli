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

// IPCommand returns the policy subcommand.
func IPCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "ip")
	return cli.Command{
		Name:  "ip",
		Usage: "add or remove ip addresses",
		UsageText: fmt.Sprintf(`**%s** <ip address> [**--remove**]
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages IP addresses and ranges in policies

## EXAMPLES

Allow IP address 127.0.0.1 in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow ip 127.0.0.1
'''

Allow IP address range 10.0.0.0/24 in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow ip 10.0.0.0/24
'''

Deny IP address 10.0.0.30 in X.509 certificates on authority level
'''
$ step ca policy authority x509 deny ip 10.0.0.30
'''

Remove IP address range 10.0.0.0/24 from being allowed in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow ip 10.0.0.0/24 --remove
'''

Allow IP address range 10.10.0.0/24 in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 allow ip 10.10.0.0/24 --provisioner my_provisioner
'''

Deny IP address 10.10.0.50 in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 deny ip 10.10.0.50 --provisioner my_provisioner
'''

Remove IP address 10.10.0.50 from being denied in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 deny ip 10.10.0.50 --provisioner my_provisioner --remove
'''

Allow IP address range 10.20.0.0/24 in X.509 certificates on ACME account level by EAB key reference
'''
$ step ca policy provisioner x509 allow ip 10.10.0.0/24 --provisioner my_acme_provisioner --eab-key-reference my_ref
'''

Deny IP address 10.20.0.70 in X.509 certificates on ACME account level by EAB key reference
'''
$ step ca policy provisioner x509 deny ip 10.20.0.70 --provisioner my_acme_provisioner --eab-key-reference my_ref
'''

Remove IP address 10.20.0.70 from being denied in X.509 certificates on ACME account level by EAB key reference
'''
$ step ca policy provisioner x509 deny ip 10.20.0.70 --provisioner my_acme_provisioner --eab-key-reference my_ref --remove
'''

Allow IP address range 192.168.0.0/24 in SSH host certificates on authority level
'''
$ step ca policy authority ssh host allow ip 192.168.0.0/24
'''

Deny IP address 192.168.0.40 in SSH host certificates on authority level
'''
$ step ca policy authority ssh host deny ip 192.168.0.40
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			ipAction,
		),
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.EABKeyID,
			flags.EABReference,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided IPs from the policy instead of adding them`,
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

func ipAction(ctx context.Context) (err error) {
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
		return err
	}

	shouldRemove := clictx.Bool("remove")

	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.Host.Allow.Ips = addOrRemoveArguments(policy.Ssh.Host.Allow.Ips, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.Ssh.Host.Deny.Ips = addOrRemoveArguments(policy.Ssh.Host.Deny.Ips, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support IP addresses or ranges")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.Ips = addOrRemoveArguments(policy.X509.Allow.Ips, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.Ips = addOrRemoveArguments(policy.X509.Deny.Ips, args, shouldRemove)
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
