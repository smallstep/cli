package provisioner

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "provisioner",
		Usage:     "create JWKs (JSON Web Keys) and manage JWK Key Sets",
		UsageText: "step ca provisioner <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			getEncryptedKeyCommand(),
			addCommand(),
			removeCommand(),
		},
		Description: `The **step ca provisioner**

## EXAMPLES

List the active provisioners:
'''
$ step ca provisioner list
'''

Retrieve the encrypted private jwk for the given kid:
'''
$ step ca provisioner jwe-key 1234 --ca-url https://127.0.0.1 --root ./root.crt
'''

Add a single provisioner:
'''
$ step ca provisioner add max@smallstep.com max-laptop.jwk --ca-config ca.json
'''

Remove the provisioner matching a given issuer and kid:
'''
$ step ca provisioner remove max@smallstep.com --kid 1234 --ca-config ca.json
'''`,
	}
}
