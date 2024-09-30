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

// DNSCommand returns the dns policy subcommand.
func DNSCommand(ctx context.Context) cli.Command {
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "dns")
	return cli.Command{
		Name:  "dns",
		Usage: "add or remove DNS domains",
		UsageText: fmt.Sprintf(`**%s** <domain> [**--remove**]
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages DNS domains in policies

## EXAMPLES

Allow www.example.com DNS in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow dns www.example.com
'''

Allow all DNS subdomains of "local" in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow dns "*.local"
'''

Deny DNS badhost.local in X.509 certificates on authority level
'''
$ step ca policy authority x509 deny dns "badhost.local"
'''

Remove badhost.local from denied DNS names in X.509 certificates on authority level
'''
$ step ca policy authority x509 deny dns "badhost.local" --remove
'''

Allow all DNS subdomains of "example.com" in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 allow dns "*.example.com" --provisioner my_provisioner
'''

Allow all DNS subdomains of "account1.acme.example.com" in X.509 certificates on ACME Account level
'''
$ step ca policy acme x509 allow dns "*.account1.acme.example.com" --provisioner my_acme_provisioner --reference account1
'''

Allow all DNS subdomains of "local" in SSH host certificates on authority level
'''
$ step ca policy authority ssh host allow dns "*.local"
'''

Deny badsshhost.local in SSH host certificates on authority level
'''
$ step ca policy authority ssh host allow dns "badsshhost.local"
'''`, commandName),
		Action: command.InjectContext(
			ctx,
			dnsAction,
		),
		Flags: []cli.Flag{
			provisionerFilterFlag,
			flags.EABKeyID,
			flags.EABReference,
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided DNS names from the policy instead of adding them`,
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

func dnsAction(ctx context.Context) (err error) {
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
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.Host.Allow.Dns = addOrRemoveArguments(policy.Ssh.Host.Allow.Dns, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.Ssh.Host.Deny.Dns = addOrRemoveArguments(policy.Ssh.Host.Deny.Dns, args, shouldRemove)
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support DNS names")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.Dns = addOrRemoveArguments(policy.X509.Allow.Dns, args, shouldRemove)
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.Dns = addOrRemoveArguments(policy.X509.Deny.Dns, args, shouldRemove)
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
