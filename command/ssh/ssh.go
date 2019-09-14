package ssh

import (
	"github.com/smallstep/cli/command"
	"github.com/urfave/cli"
)

// init creates and registers the ssh command
func init() {
	cmd := cli.Command{
		Name:      "ssh",
		Usage:     "create and manage ssh certificates",
		UsageText: "step ssh <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ssh** command group provides facilities to sign SSH certificates.

## EXAMPLES

Generate a new SSH key pair and user certificate:
'''
$ step ssh certificate mariano@work id_ecdsa
'''

Generate a new SSH key pair and host certificate:
'''
$ step ssh certificate --host internal.example.com ssh_host_ecdsa_key
'''`,
		Subcommands: cli.Commands{
			certificateCommand(),
			loginCommand(),
		},
	}

	command.Register(cmd)
}
