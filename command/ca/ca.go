package ca

import (
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/command/ca/provisioner"
	"github.com/urfave/cli"
)

// init creates and registers the ca command
func init() {
	cmd := cli.Command{
		Name:      "ca",
		Usage:     "TODO",
		UsageText: "step ca <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `
**step ca** command group provides facilities initialize a certificate
authority, sign and renew certificate, ...

## Examples

Create the configuration for a new certificate authority:
'''
$ step ca init
'''

Download the root_ca.crt:
'''
$ step ca root root_ca.crt \
  --ca-url https://ca.smallstep.com \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Create a new certificate using a token:
'''
$ TOKEN=$(step ca new-token internal.example.com)
$ step ca new-certificate internal.example.com internal.crt internal.key \
  --token $TOKEN --ca-url https://ca.smallstep.com --root root_ca.crt
'''

Renew the certificate while is still valid:
'''
$ step ca renew internal.crt internal.key \
  --ca-url https://ca.smallstep.com --root root_ca.crt
'''

Configure the ca-url and root in the environment:
'''
$ cp root_ca.crt $STEPPATH/secrets/
$ cat \> $STEPPATH/config/defaults.json
{
    "ca-url": "https://ca.smallstep.com",
    "root": "/home/user/.step/secrets/root_ca.crt"
}
'''`,
		Subcommands: cli.Commands{
			initCommand(),
			newTokenCommand(),
			newCertificateCommand(),
			signCertificateCommand(),
			rootComand(),
			renewCertificateCommand(),
			provisioner.Command(),
		},
	}

	command.Register(cmd)
}
