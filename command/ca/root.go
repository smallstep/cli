package ca

import (
	"crypto/tls"
	"net/http"

	"github.com/pkg/errors"

	"github.com/smallstep/ca-component/ca"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func rootComand() cli.Command {
	return cli.Command{
		Name:   "root",
		Action: cli.ActionFunc(rootAction),
		Usage:  "downloads and validates the root certificate",
		UsageText: `**step ca root** <root-file>
		[--fingerprint=<fingerprint>] [**--ca-url**=<uri>]`,
		Description: `**step ca root** downloads and validates the root certificate from the
certificate authority.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "fingerprint",
				Usage: "The <fingerprint> of the targeted root certificate.",
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
		},
	}
}

func rootAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	caURL := ctx.String("ca-url")
	fingerprint := ctx.String("fingerprint")
	rootFile := ctx.Args().Get(0)

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

	resp, err := client.Root(fingerprint)
	if err != nil {
		return errors.Wrap(err, "error downloading root certificate")
	}

	_, err = pemutil.Serialize(resp.RootPEM.Certificate, pemutil.ToFile(rootFile, 0600))
	return err
}

func getInsecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
