package key

import (
	"github.com/urfave/cli"
)

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "key",
		Usage:     "manage keys",
		UsageText: "step crypto key SUBCOMMAND [ARGUMENTS] [GLOBAL_FLAGS] [SUBCOMMAND_FLAGS]",
		Description: `**step crypto key** command group provides facilities for
managing cryptographic keys.

## EXAMPLES

Convert PEM format to PKCS8.
'''
$ step crypto key format foo-key.pem
'''
`,

		Subcommands: cli.Commands{
			formatCommand(),
			publicCommand(),
			inspectCommand(),
		},
	}
}
