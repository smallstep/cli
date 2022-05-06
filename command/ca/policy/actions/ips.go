package actions

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// Command returns the policy subcommand.
func IPCommand(ctx context.Context) cli.Command {

	return cli.Command{
		Name:  "ip",
		Usage: "...",
		UsageText: `**ip** <ip address> [**--remove**]
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-reference**=<eab-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**ip** command group provides facilities for ...`,
		Action: command.InjectContext(
			ctx,
			ipAction,
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
			cli.BoolFlag{
				Name:  "remove",
				Usage: `removes the provided IPs from the policy instead of adding them`,
			},
		},
	}
}

func ipAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)

	args := clictx.Args()
	if len(args) == 0 {
		return errors.New("please provide at least one IP address or range")
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return err
	}

	var ips []string
	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			ips = policy.Ssh.Host.Allow.Ips
		case policycontext.IsDeny(ctx):
			ips = policy.Ssh.Host.Deny.Ips
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support IP addresses or ranges")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			ips = policy.X509.Allow.Ips
		case policycontext.IsDeny(ctx):
			ips = policy.X509.Deny.Ips
		default:
			panic("no allow nor deny context set")
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	if clictx.Bool("remove") {
		for _, ip := range args {
			if err := validate(ip); err != nil {
				return err
			}
			ips = remove(ip, ips)
		}
	} else {
		for _, ip := range args {
			if err := validate(ip); err != nil {
				return err
			}
		}
		// add all new ips to the existing ips
		ips = append(ips, args...)
	}

	switch {
	case policycontext.IsSSHHostPolicy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.Ssh.Host.Allow.Ips = ips
		case policycontext.IsDeny(ctx):
			policy.Ssh.Host.Deny.Ips = ips
		default:
			panic(errors.New("no allow nor deny context set"))
		}
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support IP addresses or ranges")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.Ips = ips
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.Ips = ips
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

	return prettyPrint(updatedPolicy)
}

func validate(ipOrCIDR string) error {
	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(ipOrCIDR); err == nil {
		return nil
	}
	return fmt.Errorf("%s is not a valid IP address or CIDR", ipOrCIDR)
}
