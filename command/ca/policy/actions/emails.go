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

// EmailCommand returns the x509 email subcommand
func EmailCommand(ctx context.Context) cli.Command {

	return cli.Command{
		Name:  "email",
		Usage: "...",
		UsageText: `**email** <domain> [**--remove**]
[**--provisioner**=<name>] [**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**dns** command group provides facilities for ...`,
		Action: command.InjectContext(
			ctx,
			emailAction,
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
				Usage: `removes the provided emails from the policy instead of adding them`,
			},
		},
	}
}

func emailAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)

	args := clictx.Args()
	if len(args) == 0 {
		return errors.New("please provide at least one email (domain)")
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return err
	}

	var emails []string
	switch {
	case policycontext.HasSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support emails")
	case policycontext.HasSSHUserPolicy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			emails = policy.Ssh.User.Allow.Emails
		case policycontext.HasDeny(ctx):
			emails = policy.Ssh.User.Deny.Emails
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.HasX509Policy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			emails = policy.X509.Allow.Emails
		case policycontext.HasDeny(ctx):
			emails = policy.X509.Deny.Emails
		default:
			panic("no allow nor deny context set")
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	if clictx.Bool("remove") {
		for _, email := range args {
			emails = remove(email, emails)
		}
	} else {
		// add all new emails to the existing emails
		emails = append(emails, args...)
	}

	switch {
	case policycontext.HasSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support emails")
	case policycontext.HasSSHUserPolicy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			policy.Ssh.User.Allow.Emails = emails
		case policycontext.HasDeny(ctx):
			policy.Ssh.User.Deny.Emails = emails
		default:
			panic("no allow nor deny context set")
		}
	case policycontext.HasX509Policy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			policy.X509.Allow.Emails = emails
		case policycontext.HasDeny(ctx):
			policy.X509.Deny.Emails = emails
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

	prettyPrint(updatedPolicy)

	return nil
}
