package ca

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/smallstep/truststore"
	"github.com/urfave/cli"
)

func bootstrapCommand() cli.Command {
	return cli.Command{
		Name:      "bootstrap",
		Action:    command.ActionFunc(bootstrapAction),
		Usage:     "initialize the environment to use the CA commands",
		UsageText: `**step ca bootstrap** [**--ca-url**=<uri>] [**--fingerprint**=<fingerprint>] [**--install**]`,
		Description: `**step ca bootstrap** downloads the root certificate from the certificate
authority and sets up the current environment to use it.

Bootstrap will store the root certificate in <$STEPPATH/certs/root_ca.crt> and
create a configuration file in <$STEPPATH/configs/defaults.json> with the CA
url, the root certificate location and its fingerprint.

After the bootstrap, ca commands do not need to specify the flags
--ca-url, --root or --fingerprint if we want to use the same environment.`,
		Flags: []cli.Flag{
			flags.CaURL,
			fingerprintFlag,
			flags.Team,
			cli.BoolFlag{
				Name:  "install",
				Usage: "Install the root certificate into the system truststore.",
			},
			flags.Force,
		},
	}
}

type bootstrapConfig struct {
	CA          string `json:"ca-url"`
	Fingerprint string `json:"fingerprint"`
	Root        string `json:"root"`
}

func bootstrapAction(ctx *cli.Context) error {
	caURL := ctx.String("ca-url")
	fingerprint := ctx.String("fingerprint")
	team := ctx.String("team")
	rootFile := pki.GetRootCAPath()
	configFile := filepath.Join(config.StepPath(), "config", "defaults.json")

	switch {
	case team != "":
		return cautils.BootstrapTeam(ctx, team)
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
