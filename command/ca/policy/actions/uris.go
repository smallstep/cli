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

// Command returns the policy subcommand.
func URICommand(ctx context.Context) cli.Command {

	return cli.Command{
		Name:  "uri",
		Usage: "...",
		UsageText: `**uri** <domain> [**--remove**]
[**--provisioner**=<name>] [**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**uri** command group provides facilities for ...`,
		Action: command.InjectContext(
			ctx,
			uriAction,
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
				Usage: `removes the provided URIs from the policy instead of adding them`,
			},
		},
	}
}

func uriAction(ctx context.Context) (err error) {

	clictx := command.CLIContextFromContext(ctx)

	args := clictx.Args()
	if len(args) == 0 {
		return errors.New("please provide at least one URI")
	}

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return fmt.Errorf("error retrieving policy: %w", err)
	}

	var uris []string
	switch {
	case policycontext.HasSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support URIs")
	case policycontext.HasSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support URIs")
	case policycontext.HasX509Policy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			uris = policy.X509.Allow.Uris
		case policycontext.HasDeny(ctx):
			uris = policy.X509.Deny.Uris
		default:
			panic(errors.New("no allow nor deny context set"))
		}
	default:
		panic("no SSH nor X.509 context set")
	}

	if clictx.Bool("remove") {
		for _, uri := range args {
			uris = remove(uri, uris)
		}
	} else {
		uris = append(uris, args...)
	}

	switch {
	case policycontext.HasSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support URIs")
	case policycontext.HasSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support URIs")
	case policycontext.HasX509Policy(ctx):
		switch {
		case policycontext.HasAllow(ctx):
			policy.X509.Allow.Uris = uris
		case policycontext.HasDeny(ctx):
			policy.X509.Deny.Uris = uris
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
