package ca

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/smallstep/truststore"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
)

func bootstrapCommand() cli.Command {
	return cli.Command{
		Name:   "bootstrap",
		Action: command.ActionFunc(bootstrapAction),
		Usage:  "initialize the environment to use the CA commands",
		UsageText: `**step ca bootstrap**
[**--ca-url**=<uri>] [**--fingerprint**=<fingerprint>] [**--install**]
[**--team**=name] [**--team-url**=url] [**--redirect-url**=<url>]`,
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
			flags.TeamURL,
			flags.RedirectURL,
			flags.Force,
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
	rootFile := pki.GetRootCAPath()
	configFile := filepath.Join(step.Path(), "config", "defaults.json")
	redirectURL := ctx.String("redirect-url")

	switch {
	case team != "":
		return cautils.BootstrapTeam(ctx, team)
	case caURL == "":
		return errs.RequiredFlag(ctx, "ca-url")
	case fingerprint == "":
		return errs.RequiredFlag(ctx, "fingerprint")
	}

	tr := getInsecureTransport()
	client, err := ca.NewClient(caURL, ca.WithTransport(tr))
	if err != nil {
		return err
	}

	// Root already validates the certificate
	resp, err := client.Root(fingerprint)
	if err != nil {
		return errors.Wrap(err, "error downloading root certificate")
	}

	if err = os.MkdirAll(filepath.Dir(rootFile), 0700); err != nil {
		return errs.FileError(err, rootFile)
	}

	if err = os.MkdirAll(filepath.Dir(configFile), 0700); err != nil {
		return errs.FileError(err, configFile)
	}

	// Serialize root
	_, err = pemutil.Serialize(resp.RootPEM.Certificate, pemutil.ToFile(rootFile, 0600))
	if err != nil {
		return err
	}
	ui.Printf("The root certificate has been saved in %s.\n", rootFile)

	// make sure to store the url with https
	caURL, err = completeURL(caURL)
	if err != nil {
		return err
	}

	// Serialize defaults.json
	b, err := json.MarshalIndent(bootstrapConfig{
		CA:          caURL,
		Fingerprint: fingerprint,
		Root:        pki.GetRootCAPath(),
		Redirect:    redirectURL,
	}, "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling defaults.json")
	}

	if err := utils.WriteFile(configFile, b, 0644); err != nil {
		return err
	}

	ui.Printf("Your configuration has been saved in %s.\n", configFile)

	if ctx.Bool("install") {
		ui.Printf("Installing the root certificate in the system truststore... ")
		if err := truststore.InstallFile(rootFile); err != nil {
			ui.Println()
			return err
		}
		ui.Println("done.")
	}

	return nil
}
