package crl

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
)

// init creates and registers the crl command
func init() {
	cmd := cli.Command{
		Name:      "crl",
		Usage:     "initialize and manage a certificate revocation list",
		UsageText: "**step crl** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crl** command group provides facilities to create, manage and inspect a
certificate revocation list (CRL).

## EXAMPLES

Inspect a CRL:
'''
$ step crl inspect http://ca.example.com/crls/exampleca.crl
'''`,
		Subcommands: cli.Commands{
			inspectCommand(),
		},
	}

	command.Register(cmd)
}
