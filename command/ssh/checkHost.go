package ssh

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	caErrs "github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/utils/cautils"
)

func checkHostCommand() cli.Command {
	return cli.Command{
		Name:   "check-host",
		Action: command.ActionFunc(checkHostAction),
		Usage:  "checks if a certificate has been issued for a host",
		UsageText: `**step ssh check-host** <hostname> [**--verbose,-v**]
[**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Description: `**step ssh check-host** checks if a certificate has been issued for a host.

This command returns a zero exit status if the host has a certificate.
Otherwise, it returns 1.

## POSITIONAL ARGUMENTS

<hostname>
:  The hostname of the server to check.

## EXAMPLES

Check that internal.example.com exists:
'''
$ step ssh check-host internal.smallstep.com
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "verbose, v",
				Usage: `Return "true" or "false" in the terminal.`,
			},
			flags.CaConfig,
			flags.Offline,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func checkHostAction(ctx *cli.Context) error {
	isVerbose := ctx.Bool("verbose")

	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	client, err := cautils.NewClient(ctx)
	if err != nil {
		return contactAdminErr(errors.Wrap(err, "error generating ca client"))
	}
	version, err := client.Version()
	if err != nil {
		return contactAdminErr(errors.Wrap(err, "error retrieving client version info"))
	}

	var (
		tok      string
		hostname = ctx.Args().First()
	)
	if version.RequireClientAuthentication {
		id, err := ca.LoadDefaultIdentity()
		if err != nil {
			return sshConfigErr(errors.Wrap(err, "error loading the default x5c identity"))
		}

		if id != nil {
			// Get private key from given key file.
			jwk, err := jose.ReadKey(id.Key)
			if err != nil {
				return debugErr(errors.Wrap(err, "error parsing x5c key from identity file"))
			}
			tokenGen := cautils.NewTokenGenerator(jwk.KeyID, "x5c-identity",
				"/ssh/check-host", "", time.Time{}, time.Time{}, jwk)
			tok, err = tokenGen.Token(hostname, token.WithX5CInsecureFile(id.Certificate, jwk.Key))
			if err != nil {
				return sshConfigErr(errors.Wrap(err, "error generating identity x5c token for /ssh/check-host request"))
			}
		}
	}

	resp, err := client.SSHCheckHost(hostname, tok)
	if err != nil {
		return caErrs.Wrap(http.StatusInternalServerError, err,
			"error checking ssh host eligibility")
	}

	if isVerbose {
		fmt.Println(resp.Exists)
	}
	if !resp.Exists {
		os.Exit(1)
	}
	return nil
}
