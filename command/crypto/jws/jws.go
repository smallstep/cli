package jws

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "jws",
		Usage:     "sign and verify data using JSON Web Signature (JWS)",
		UsageText: "step crypto jws <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `JSON Web Signature (JWS) represents content secured with digital signatures or
Message Authentication Codes (MACs) using JSON-based data structures.`,
		Subcommands: cli.Commands{
			signCommand(),
			inspectCommand(),
			verifyCommand(),
		},
	}
}
