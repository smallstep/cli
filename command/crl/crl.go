package crl

import (
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
)

// init creates and registers the crl command
func init() {
	cmd := cli.Command{
		Name:      "crl",
		Usage:     "initialize and manage a certificate revocation list",
		UsageText: "**step crl** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crl** command group provides facilities to initialize manage a
certificate revocation list or CRL.`,
		Subcommands: cli.Commands{
			inspectCommand(),
		},
	}

	command.Register(cmd)
}
