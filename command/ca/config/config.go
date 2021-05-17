package config

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "config",
		Usage:     "Manage the certificate authority configuration",
		UsageText: "step ca config <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			getCommand(),
			updateCommand(),
		},
		Description: `The **step ca config** command group provides facilities for managing the
certificate authority configuration.

## EXAMPLES

Get the configuration:
'''
$ step ca config get
'''

Update the configuration:
'''
$ step ca config update
'''`,
	}
}
