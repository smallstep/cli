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

var provisionerFilterFlag = cli.StringFlag{
	Name:  "provisioner",
	Usage: `The provisioner <name>`,
}

// Command returns the dns policy subcommand.
func DNSCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:  "dns",
		Usage: "...",
		UsageText: `**dns** <domain> [**--remove**]
[**--provisioner**=<name>] [**--key-id**=<key-id>] [**--reference**=<reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**dns** command group provides facilities for ...`,
		Action: command.InjectContext(
			ctx,
			dnsAction,
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
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided DNS names from the policy instead of adding them`,
			},
		},
	}
}

func dnsAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)

	args := clictx.Args()
	if len(args) == 0 {
		return errors.New("please provide at least one domain")
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return fmt.Errorf("error retrieving policy: %w", err)
	}

	var dns []string

	switch {
	case policycontext.HasSSHHostPolicy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			dns = policy.Ssh.Host.Allow.Dns
		case policycontext.HasDeny(ctx):
			dns = policy.Ssh.Host.Deny.Dns
		default:
			panic(errors.New("no allow nor deny context set"))
		}
	case policycontext.HasSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support DNS names")
	case policycontext.HasX509Policy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			dns = policy.X509.Allow.Dns
		case policycontext.HasDeny(ctx):
			dns = policy.X509.Deny.Dns
		default:
			panic(errors.New("no allow nor deny context set"))
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	if clictx.Bool("remove") {
		for _, domain := range args {
			dns = remove(domain, dns)
		}
	} else {
		dns = append(dns, args...)
	}

	switch {
	case policycontext.HasSSHHostPolicy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			policy.Ssh.Host.Allow.Dns = dns
		case policycontext.HasDeny(ctx):
			policy.Ssh.Host.Deny.Dns = dns
		default:
			panic(errors.New("no allow nor deny context set"))
		}
	case policycontext.HasSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support DNS names")
	case policycontext.HasX509Policy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			policy.X509.Allow.Dns = dns
		case policycontext.HasDeny(ctx):
			policy.X509.Deny.Dns = dns
		default:
			panic(errors.New("no allow nor deny context set"))
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	updatedPolicy, err := updatePolicy(ctx, client, policy)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	prettyPrint(updatedPolicy)

	return nil
}
