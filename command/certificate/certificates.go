package certificate

import (
	"github.com/smallstep/cli/command"
	"github.com/urfave/cli"
)

// Command returns the cli.Command for jwt and related subcommands.
func init() {
	cmd := cli.Command{
		Name:      "certificate",
		Usage:     "create, revoke, validate, bundle, and otherwise manage certificates.",
		UsageText: "step certificates <group | command> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step certificates** command group provides facilities for creating
  certificate signing requests (CSRs), creating self-signed certificates
  (e.g., for use as a root certificate authority), generating leaf or
  intermediate CA certificate by signing a CSR, validating certificates,
  renewing certificates, generating certificate bundles, and key-wrapping
  of private keys.

  More information about certificates in general (as opposed to the
  **step certificate** sub-commands) can be found at **step help topics certificate**
  or online at [URL].`,

		Subcommands: cli.Commands{
			bundleCommand(),
			createCommand(),
			inspectCommand(),
			lintCommand(),
			//renewCommand(),
			signCommand(),
			verifyCommand(),
		},
	}

	command.Register(cmd)
}
