package ca

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/truststore"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
)

func bootstrapHelperCommand() cli.Command {
	return cli.Command{
		Hidden: true,
		Name:   "bootstrap-helper",
		Action: command.ActionFunc(bootstrapHelperAction),
		Usage:  "initialize the environment to use the CA commands",
		UsageText: `**step ca bootstrap-helper**
[**--ca-url**=<uri>] [**--fingerprint**=<fingerprint>] [**--install**]
[**--redirect-url**=<uri>]`,
		Description: `**step ca bootstrap-helper** downloads the root certificate from the certificate
authority and sets up the current environment to use it.

Bootstrap will store the root certificate in <$STEPPATH/certs/root_ca.crt> and
create a configuration file in <$STEPPATH/configs/defaults.json> with the CA
url, the root certificate location and its fingerprint.

After the bootstrap, ca commands do not need to specify the flags
--ca-url, --root or --fingerprint if we want to use the same environment.

## EXAMPLES

Bootstrap using the CA url and a fingerprint:
'''
$ step ca bootstrap-helper --ca-url https://ca.example.org \
  --fingerprint d9d0978692f1c7cc791f5c343ce98771900721405e834cd27b9502cc719f5097
'''

Bootstrap and install the root certificate
'''
$ step ca bootstrap-helper --ca-url https://ca.example.org \
  --fingerprint d9d0978692f1c7cc791f5c343ce98771900721405e834cd27b9502cc719f5097 \
  --install
'''
`,
		Flags: []cli.Flag{
			flags.CaURL,
			fingerprintFlag,
			cli.BoolFlag{
				Name:  "install",
				Usage: "Install the root certificate into the system truststore.",
			},
			flags.RedirectURL,
			flags.Force,
			flags.Context,
		},
	}
}

func bootstrapHelperAction(ctx *cli.Context) error {
	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return err
	}
	fingerprint := ctx.String("fingerprint")
	redirectURL := ctx.String("redirect-url")

	switch {
	case len(caURL) == 0:
		return errs.RequiredFlag(ctx, "ca-url")
	case len(fingerprint) == 0:
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

	rootFile := pki.GetRootCAPath()
	configFile := filepath.Join(step.Path(), "config", "defaults.json")

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

	ui.Printf("The authority configuration has been saved in %s.\n", configFile)

	if step.IsContextEnabled() {
		profileDefaultsFile := filepath.Join(step.ProfilePath(), "config", "defaults.json")

		if err := os.MkdirAll(filepath.Dir(profileDefaultsFile), 0700); err != nil {
			return errs.FileError(err, profileDefaultsFile)
		}

		if _, err := os.Stat(profileDefaultsFile); os.IsNotExist(err) {
			if err := ioutil.WriteFile(profileDefaultsFile, []byte("{}"), 0600); err != nil {
				return errs.FileError(err, profileDefaultsFile)
			}
			ui.Printf("The profile configuration has been saved in %s.\n", profileDefaultsFile)
		}
	}

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
