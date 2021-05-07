package admin

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "admin",
		Usage:     "create and manage the certificate authority admins",
		UsageText: "step ca admin <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			//getCommand(),
			addCommand(),
			//removeCommand(),
		},
		Description: `The **step ca admin** command group provides facilities for managing the
certificate authority admins.

A admin is an entity that manages administrative resources within a certificate
authority. Admins manage

* certificate authority configuration
* provisioner configuration
* other admins and admin privileges

## EXAMPLES

List the active admins:
'''
$ step ca admin list
'''

Add an admin:
'''
$ step ca admin add max@smallstep.com my-jwk-provisioner
'''

Remove an admin:
'''
$ step ca admin remove max@smallstep.com my-jwk-provisioner
'''`,
	}
}
