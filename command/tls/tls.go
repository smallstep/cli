package tls

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
)

// Command returns the cli.Command for jwt and related subcommands.
func init() {
	cmd := cli.Command{
		Name:      "tls",
		Usage:     "tls inspection utilities",
		UsageText: "step tls SUBCOMMAND [ARGUMENTS] [GLOBAL_FLAGS] [SUBCOMMAND_FLAGS]",
		Description: `**step tls** command group provides facilities for 
inspecting TLS services.

## EXAMPLES

Do a TLS handshake:
'''
$ step tls handshake https://smallstep.com
'''
`,

		Subcommands: cli.Commands{
			handshakeCommand(),
		},
	}

	command.Register(cmd)
}
