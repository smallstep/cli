package nssdb

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
)

// Command returns the cli.Command for jwt and related subcommands.
func init() {
	cmd := cli.Command{
		Name:      "nssdb",
		Usage:     "manage certificates and keys in an NSS database",
		UsageText: "step nssdb SUBCOMMAND [ARGUMENTS] [GLOBAL_FLAGS] [SUBCOMMAND_FLAGS]",
		Description: `**step nssdb** command group provides facilities for importing,
exporting, and viewing certificates and keys in an NSS database.
Firefox, Chrome, and other browsers and applications that use NSS
databases will then be able to make TLS connections with the imported
objects. This command implements a subset of the features offered by
the certutil, pk12util, and modutil commands from NSS.

## EXAMPLES

Import a certificate into the default user NSS database on Linux used by Chrome.
'''
$ step nssdb import foo.crt --dir ~/.pki/nssdb
'''
`,

		Subcommands: cli.Commands{
			deleteCommand(),
			importCommand(),
			listCommand(),
			rawCommand(),
			resetCommand(),
		},
	}

	command.Register(cmd)
}
