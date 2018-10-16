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

Retrieve the encrypted private jwk for the given key-id:
'''
$ step ca provisioner jwe-key 1234 --ca-url https://127.0.0.1 --root ./root.crt
'''

Add a single provisioner:
'''
$ step ca provisioner add max–laptop ./max-laptop-pub.jwk --config ca.json \
--ca-url https://127.0.0.1:8080 --root root.crt
'''

Remove the provisioner matching a given issuer and key-id:
'''
$ step ca provisioner remove max–laptop --key-id 1234 --config ca.json \
--ca-url https://127.0.0.1:8080 --root root.crt
'''`,
	}
}
