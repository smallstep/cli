package provisioner

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:        "provisioner",
		Usage:       "create JWKs (JSON Web Keys) and manage JWK Key Sets",
		UsageText:   "step ca provisioner <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `The **step ca provisioner**`,
		Subcommands: cli.Commands{
			listCommand(),
			getEncryptedKeyCommand(),
			addCommand(),
			removeCommand(),
		},
	}
}
