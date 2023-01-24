package x509

import (
	"context"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/command"
	"github.com/urfave/cli"
)

var provisionerFilterFlag = cli.StringFlag{
	Name:  "provisioner",
	Usage: `The provisioner <name>`,
}

func wildcardsCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:        "wildcards",
		Usage:       "manage wildcard name settings for X.509 certificate issuance policies",
		UsageText:   `**step ca policy x509 wildcards**`,
		Description: `**step ca policy x509 wildcards** command group provides facilities for managing X.509 wildcard names.`,
		Subcommands: cli.Commands{
			allowWildcardsCommand(ctx),
			denyWildcardsCommand(ctx),
		},
	}
}

func allowWildcardsCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:  "allow",
		Usage: "allow wildcard names in X.509 certificate issuance policies",
		UsageText: `**step ca policy x509 wildcards allow**
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Description: `**step ca policy x509 wildcards allow** allow wildcard names in X.509 policy

## EXAMPLES	

Allow wildcard names in X.509 certificates on authority level
'''
$ step ca policy authority x509 wildcards allow
'''		

Allow wildcard names in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 wildcards allow --provisioner my_provisioner
'''		

Allow wildcard names in X.509 certificates on ACME account level by reference
'''
$ step ca policy acme x509 wildcards allow --provisioner my_acme_provisioner --eab-reference my_reference
'''`,
		Action: command.InjectContext(
			ctx,
			actions.AllowWildcardsAction,
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

func denyWildcardsCommand(ctx context.Context) cli.Command {
	return cli.Command{
		Name:  "deny",
		Usage: "deny wildcard names in X.509 certificate issuance policies",
		UsageText: `**step ca policy x509 wildcards deny**
[**--provisioner**=<name>] [**--eab-key-id**=<eab-key-id>] [**--eab-key-reference**=<eab-key-reference>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Description: `**step ca policy x509 wildcards deny** deny wildcard names in X.509 policy

## EXAMPLES	

Deny wildcard names in X.509 certificates on authority level
'''
$ step ca policy authority x509 wildcards deny
'''		

Deny wildcard names in X.509 certificates on provisioner level
'''
$ step ca policy provisioner x509 wildcards deny --provisioner my_provisioner
'''		

Deny wildcard names in X.509 certificates on ACME account level by reference
'''
$ step ca policy acme x509 wildcards deny --provisioner my_acme_provisioner --eab-reference my_reference
'''`,
		Action: command.InjectContext(
			ctx,
			actions.DenyWildcardsAction,
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
