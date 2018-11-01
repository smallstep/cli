package provisioner

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "provisioner",
		Usage:     "create and manage the certificate authority provisioners",
		UsageText: "step ca provisioner <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			getEncryptedKeyCommand(),
			addCommand(),
			removeCommand(),
		},
		Description: `The **step ca provisioner** command group provides facilities for managing the
certificate authority provisioner.

A provisioner is an entity that controls provisioning credentials, which are
used to generate provisioning tokens.

Provisioning credentials are simple JWK key pairs using public-key cryptography.
The public key is used to verify a provisioning token while the private key is
used to sign the provisioning token.

Provisioning tokens are JWT tokens signed by the JWK private key. These JWT
tokens are used to get a valid TLS certificate from the certificate authority.
Each provisioner is able to manage a different set of rules that can be used to
configure the bounds of the certificate.

In the certificate authority, a provisioner is configured with a JSON object
with the following properties:

* **name**: the provisioner name, it will become the JWT issuer and a good
  practice is to use an email address for this.
* **type**: the provisioner type, currently only "jwk" is supported.
* **key**: the JWK public key used to verify the provisioning tokens.
* **encryptedKey** (optional): the JWE compact serialization of the private key
  used to sign the provisioning tokens.
* **claims** (optional): an object with custom options for each provisioner.
  Options supported are:
  * **minTLSCertDuration**: minimum duration of a certificate, set to 5m by
    default.
  * **maxTLSCertDuration**: maximum duration of a certificate, set to 24h by
    default.
  * **defaultTLSCertDuration**: default duration of the certificate, set to 24h
    by default.

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
