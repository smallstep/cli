package ca

import (
	"github.com/smallstep/cli/command"
	"github.com/urfave/cli"
)

// init creates and registers the ca command
func init() {
	cmd := cli.Command{
		Name:        "ca",
		Usage:       "TODO",
		UsageText:   "step ca <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca** command group provides facilities ... TODO`,
		Subcommands: cli.Commands{
			initCommand(),
			newTokenCommand(),
			newCertificateCommand(),
			signCertificateCommand(),
			rootComand(),
			renewCertificateCommand(),
			provisionersCommand(),
			provisioningKeyCommand(),
		},
	}

	command.Register(cmd)
}
