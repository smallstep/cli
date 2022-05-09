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
	commandName := policycontext.GetPrefixedCommandUsage(ctx, "uri")
	return cli.Command{
		Name:  "uri",
		Usage: "add or remove URI domains",
		UsageText: fmt.Sprintf(`**%s** <uri domain> [**--remove**]
[**--provisioner**=<name>] [**--admin-cert**=<file>] [**--admin-key**=<file>]
[**--admin-provisioner**=<string>] [**--admin-subject**=<string>]
[**--password-file**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`, commandName),
		Description: fmt.Sprintf(`**%s** command manages URI domains in policies
		
## EXAMPLES	

Allow all URI subdomains of "local" in X.509 certificates on authority level
'''
$ step ca policy authority x509 allow uri "*.local"
'''

Deny URI badhost.local domain in X.509 certificates on authority level
'''
$ step ca policy authority x509 deny uri badhost.local
'''

Remove badhost.local from denied URI domain names in X.509 certificates on authority level
'''
$ step ca policy authority x509 deny uri badhost.local --remove
'''

Allow all URI subdomains of "example.com" in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 allow uri "*.example.com" --provisioner my_provisioner
'''
		
`, commandName),
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
	case policycontext.IsSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support URIs")
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support URIs")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			uris = policy.X509.Allow.Uris
		case policycontext.IsDeny(ctx):
			uris = policy.X509.Deny.Uris
		default:
			panic("no allow nor deny context set")
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
	case policycontext.IsSSHHostPolicy(ctx):
		return errors.New("SSH host policy does not support URIs")
	case policycontext.IsSSHUserPolicy(ctx):
		return errors.New("SSH user policy does not support URIs")
	case policycontext.IsX509Policy(ctx):
		switch {
		case policycontext.IsAllow(ctx):
			policy.X509.Allow.Uris = uris
		case policycontext.IsDeny(ctx):
			policy.X509.Deny.Uris = uris
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
