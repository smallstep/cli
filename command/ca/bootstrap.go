package ca

import (
	"strings"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
)

func bootstrapCommand() cli.Command {
	return cli.Command{
		Name:   "bootstrap",
		Action: command.ActionFunc(bootstrapAction),
		Usage:  "initialize the environment to use the CA commands",
		UsageText: `**step ca bootstrap**
[**--ca-url**=<uri>] [**--fingerprint**=<fingerprint>] [**--install**]
[**--team**=<name>] [**--authority**=<name>] [**--team-url**=<uri>] [**--redirect-url**=<uri>]
[**--context**=<string>] [**--profile**=<string>] [**--authority**=<string>]`,
		Description: `**step ca bootstrap** downloads the root certificate from the certificate
authority and sets up the current environment to use it.

Bootstrap will store the root certificate in <$STEPPATH/certs/root_ca.crt> and
create a configuration file in <$STEPPATH/configs/defaults.json> with the CA
url, the root certificate location and its fingerprint.

After the bootstrap, ca commands do not need to specify the flags
--ca-url, --root or --fingerprint if we want to use the same environment.

## EXAMPLES

Bootstrap using the CA url and a fingerprint:
'''
$ step ca bootstrap --ca-url https://ca.example.org \
  --fingerprint d9d0978692f1c7cc791f5c343ce98771900721405e834cd27b9502cc719f5097
'''

Bootstrap and install the root certificate
'''
$ step ca bootstrap --ca-url https://ca.example.org \
  --fingerprint d9d0978692f1c7cc791f5c343ce98771900721405e834cd27b9502cc719f5097 \
  --install
'''

Bootstrap with a smallstep.com CA using a team ID:
'''
$ step ca bootstrap --team superteam
'''

To use team IDs in your own environment, you'll need an HTTP(S) server
serving a JSON file:
'''
{"url":"https://ca.example.org","fingerprint":"d9d0978692f1c7cc791f5c343ce98771900721405e834cd27b9502cc719f5097"}
'''

Then, this command will look for the file at https://config.example.org/superteam:
'''
$ step ca bootstrap --team superteam --team-url https://config.example.org/<>
'''`,
		Flags: []cli.Flag{
			flags.CaURL,
			fingerprintFlag,
			cli.BoolFlag{
				Name:  "install",
				Usage: "Install the root certificate into the system truststore.",
			},
			flags.Team,
			cli.StringFlag{
				Name: "authority-subdomain",
				Usage: `The <sub-domain> of the authority to bootstrap. E.g., for an authority with
domain name 'certs.example-team.ca.smallstep.com' the value would be 'certs'.`,
			},
			flags.TeamURL,
			flags.RedirectURL,
			flags.Force,
			flags.Context,
			flags.ContextProfile,
			flags.ContextAuthority,
		},
	}
}

type bootstrapConfig struct {
	CA          string `json:"ca-url"`
	Fingerprint string `json:"fingerprint"`
	Root        string `json:"root"`
	Redirect    string `json:"redirect-url"`
}

func bootstrapAction(ctx *cli.Context) error {
	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return err
	}
	fingerprint := strings.TrimSpace(ctx.String("fingerprint"))
	team := ctx.String("team")
	authSubdomain := ctx.String("authority-subdomain")

	switch {
	case team != "" && authSubdomain != "":
		return cautils.BootstrapTeamAuthority(ctx, team, authSubdomain)
	case team != "":
		return cautils.BootstrapTeamAuthority(ctx, team, "ssh")
	case authSubdomain != "":
		return errs.RequiredWithFlag(ctx, "authority-subdomain", "team")
	case caURL == "":
		return errs.RequiredFlag(ctx, "ca-url")
	case fingerprint == "":
		return errs.RequiredFlag(ctx, "fingerprint")
	default:
		return cautils.BootstrapAuthority(ctx, caURL, fingerprint)
	}
}
