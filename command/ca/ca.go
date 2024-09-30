package ca

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"

	"github.com/smallstep/cli/command/ca/acme"
	"github.com/smallstep/cli/command/ca/admin"
	"github.com/smallstep/cli/command/ca/policy"
	"github.com/smallstep/cli/command/ca/provisioner"
)

// init creates and registers the ca command
func init() {
	cmd := cli.Command{
		Name:      "ca",
		Usage:     "initialize and manage a certificate authority",
		UsageText: "**step ca** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca** command group provides facilities to initialize a certificate
authority, retrieve the root of trust, sign and renew certificates, and create
and manage provisioners.

## EXAMPLES

Create the configuration for a new certificate authority:
'''
$ step ca init
'''

Configure the ca-url and root in the environment:
'''
$ step ca bootstrap \
  --ca-url https://ca.smallstep.com \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
$ cat $STEPPATH/config/defaults.json
{
  "ca-url": "https://ca.smallstep.com",
  "fingerprint": "0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3",
  "root": "/home/user/.step/certs/root_ca.crt"
}
'''

Download the root_ca.crt:
'''
$ step ca root root_ca.crt \
  --ca-url https://ca.smallstep.com \
  --fingerprint 0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Get the Health status of the CA:
'''
$ step ca health --ca-url https://ca.smallstep.com --root /home/user/.step/certs/root_ca.crt
'''

Create a new certificate using a token:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate internal.example.com internal.crt internal.key \
  --token $TOKEN --ca-url https://ca.smallstep.com --root root_ca.crt
'''

Renew a certificate (certificate must still be valid):
'''
$ step ca renew internal.crt internal.key \
  --ca-url https://ca.smallstep.com --root root_ca.crt
'''`,
		Subcommands: cli.Commands{
			healthCommand(),
			initCommand(),
			bootstrapCommand(),
			tokenCommand(),
			certificateCommand(),
			rekeyCertificateCommand(),
			renewCertificateCommand(),
			revokeCertificateCommand(),
			provisioner.Command(),
			signCertificateCommand(),
			rootCommand(),
			rootsCommand(),
			federationCommand(),
			acme.Command(),
			policy.Command(),
			admin.Command(),
		},
	}

	command.Register(cmd)
}

// common flags used in several commands
var (
	acmeFlag = cli.StringFlag{
		Name: "acme",
		Usage: `ACME directory <url> to be used for requesting certificates via the ACME protocol.
Use this flag to define an ACME server other than the Step CA. If this flag is
absent and an ACME provisioner has been selected then the '--ca-url' flag must be defined.`,
	}

	acmeContactFlag = cli.StringSliceFlag{
		Name: "contact",
		Usage: `The <email-address> used for contact as part of the ACME protocol. These contacts
may be used to warn of certificate expiration or other certificate lifetime events.
Use the '--contact' flag multiple times to configure multiple contacts.`,
	}

	acmeHTTPListenFlag = cli.StringFlag{
		Name: "http-listen",
		Usage: `Use a non-standard http <address>, behind a reverse proxy or load balancer, for
serving ACME challenges. The default address is :80, which requires super user
(sudo) privileges. This flag must be used in conjunction with the '--standalone'
flag.`,
		Value: ":80",
	}
	/*
			TODO: Not implemented yet.
			acmeHTTPSListenFlag = cli.StringFlag{
				Name: "https-listen",
				Usage: `Use a non-standard https address, behind a reverse proxy or load balancer, for
		serving ACME challenges. The default address is :443, which requires super user
		(sudo) privileges. This flag must be used in conjunction with the '--standalone'
		flag.`,
				Value: ":443",
			}
	*/
	acmeStandaloneFlag = cli.BoolFlag{
		Name: "standalone",
		Usage: `Get a certificate using the ACME protocol and standalone mode for validation.
Standalone is a mode in which the step process will run a server that will
will respond to ACME challenge validation requests. Standalone is the default
mode for serving challenge validation requests.`,
	}

	acmeWebrootFlag = cli.StringFlag{
		Name: "webroot",
		Usage: `Specify a <file> to use as a 'web root' for validation in the ACME protocol.
Webroot is a mode in which the step process will write a challenge file to a
location being served by an existing fileserver in order to respond to ACME
challenge validation requests.`,
	}

	fingerprintFlag = cli.StringFlag{
		Name:  "fingerprint",
		Usage: "The <fingerprint> of the targeted root certificate.",
	}

	provisionerKidFlag = cli.StringFlag{
		Name:  "kid",
		Usage: "The provisioner <kid> to use.",
	}

	sshHostFlag = cli.BoolFlag{
		Name:  "host",
		Usage: `Create a host certificate instead of a user certificate.`,
	}
)

// BetaCommand enables access to beta APIs.
func BetaCommand() cli.Command {
	return cli.Command{
		Name:      "ca",
		Usage:     "commands that are made available for testing new features and APIs",
		UsageText: "**step beta ca** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step beta ca** enables beta access to new step-ca APIs. These
commands may change, disappear, or be promoted to a different subcommand in the future.`,
		Subcommands: cli.Commands{
			acme.Command(),
		},
	}
}
