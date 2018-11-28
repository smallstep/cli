package ca

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/command/ca/provisioner"
	"github.com/urfave/cli"
)

// init creates and registers the ca command
func init() {
	cmd := cli.Command{
		Name:      "ca",
		Usage:     "initialize and manage a certificate authority",
		UsageText: "step ca <subcommand> [arguments] [global-flags] [subcommand-flags]",
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
			newTokenCommand(),
			newCertificateCommand(),
			renewCertificateCommand(),
			rootComand(),
			provisioner.Command(),
			signCertificateCommand(),
		},
	}

	command.Register(cmd)
}

// common flags used in several commands
var (
	caURLFlag = cli.StringFlag{
		Name:  "ca-url",
		Usage: "<URI> of the targeted Step Certificate Authority.",
	}

	rootFlag = cli.StringFlag{
		Name:  "root",
		Usage: "The path to the PEM <file> used as the root certificate authority.",
	}

	fingerprintFlag = cli.StringFlag{
		Name:  "fingerprint",
		Usage: "The <fingerprint> of the targeted root certificate.",
	}

	tokenFlag = cli.StringFlag{
		Name: "token",
		Usage: `The one-time <token> used to authenticate with the CA in order to create the
certificate.`,
	}

	notBeforeFlag = cli.StringFlag{
		Name: "not-before",
		Usage: `The <time|duration> set in the NotBefore (nbf) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}

	notAfterFlag = cli.StringFlag{
		Name: "not-after",
		Usage: `The <time|duration> set in the Expiration (exp) property of the token. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
	}

	provisionerKidFlag = cli.StringFlag{
		Name:  "kid",
		Usage: "The provisioner <kid> to use.",
	}

	provisionerIssuerFlag = cli.StringFlag{
		Name:  "issuer",
		Usage: "The provisioner <name> to use.",
	}

	passwordFileFlag = cli.StringFlag{
		Name: "password-file",
		Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
	}
)

// completeURL parses and validates the given URL. It supports general
// URLs like https://ca.smallstep.com[:port][/path], and incomplete URLs like
// ca.smallstep.com[:port][/path].
func completeURL(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", errors.Wrapf(err, "error parsing url '%s'", rawurl)
	}

	// URLs are generally parsed as:
	// [scheme:][//[userinfo@]host][/]path[?query][#fragment]
	// But URLs that do not start with a slash after the scheme are interpreted as
	// scheme:opaque[?query][#fragment]
	if u.Opaque == "" {
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		if u.Host == "" {
			// rawurl looks like ca.smallstep.com or ca.smallstep.com/1.0/sign
			if u.Path != "" {
				parts := strings.SplitN(u.Path, "/", 2)
				u.Host = parts[0]
				if len(parts) == 2 {
					u.Path = parts[1]
				} else {
					u.Path = ""
				}
				return completeURL(u.String())
			}
			return "", errors.Errorf("error parsing url '%s'", rawurl)
		}
		return u.String(), nil
	}
	// scheme:opaque[?query][#fragment]
	// rawurl looks like ca.smallstep.com:443 or ca.smallstep.com:443/1.0/sign
	return completeURL("https://" + rawurl)
}
