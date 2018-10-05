package ca

import (
	"encoding/pem"
	"strings"

	"github.com/smallstep/cli/utils"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/ca"
	"github.com/smallstep/cli/jose"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func newCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "new-certificate",
		Action: cli.ActionFunc(newCertificateAction),
		Usage:  "generate a new certificate pair signed by the root certificate",
		UsageText: `**step ca new-certificate** <hostname> <crt-file> <key-file>
		[**--ca**=<file>] [**--ca-url**=<uri>] [**--token**=<token>]`,
		Description: `**step ca new-certificate** command generates a new certificate pair`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name: "token",
				Usage: `The one-time <token> used to authenticate with the CA in order to create the
certificate.`,
			},
		},
	}
}

func newCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	hostname := args.Get(0)
	crtFile, keyFile := args.Get(1), args.Get(2)

	root := ctx.String("ca")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	token := ctx.String("token")
	if len(token) == 0 {
		return errs.RequiredFlag(ctx, "token")
	}

	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	claims := new(jose.Claims)
	if err := tok.UnsafeClaimsWithoutVerification(claims); err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	if strings.ToLower(hostname) != strings.ToLower(claims.Subject) {
		return errors.Errorf("token subject '%s' and flag '--hostname=%s' do not match", claims.Subject, hostname)
	}

	client, err := ca.NewClient(caURL, ca.WithRootFile(root))
	if err != nil {
		return err
	}

	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return err
	}

	resp, err := client.Sign(req)
	if err != nil {
		return err
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)
	if err := utils.WriteFile(crtFile, data, 0600); err != nil {
		return err
	}

	_, err = pemutil.Serialize(pk, pemutil.ToFile(keyFile, 0600))
	if err != nil {
		return err
	}

	return nil
}
