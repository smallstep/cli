package ca

import (
	"context"
	"encoding/pem"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

type flowType int

const (
	rootsFlow flowType = iota
	federationFlow
)

func rootsCommand() cli.Command {
	return cli.Command{
		Name:   "roots",
		Action: command.ActionFunc(rootsAction),
		Usage:  "download all the root certificates",
		UsageText: `**step ca roots** <roots-file>
		[**--token**=<token>]`,
		Description: `**step ca roots** downloads a certificate bundle with all the root
certificates. The request to download the bundle requires
a mTLS connection with the certificate authority, the command creates a 
temporal certificate using the token and then does a mTLS request to the 
CA.

## POSITIONAL ARGUMENTS

<roots-file>
:  File to write all the root certificates (PEM format)`,
		Flags: []cli.Flag{
			tokenFlag,
			flags.Force,
		},
	}
}

func federationCommand() cli.Command {
	return cli.Command{
		Name:   "federation",
		Action: command.ActionFunc(federationAction),
		Usage:  "download all the federated certificates",
		UsageText: `**step ca federation** <federation-file>
		[**--token**=<token>]`,
		Description: `**step ca federation** downloads a certificate bundle with all the root
certificates in the federation. The request to download the bundle requires
a mTLS connection with the certificate authority, the command creates a 
temporal certificate using the token and then does a mTLS request to the 
CA.

## POSITIONAL ARGUMENTS

<federation-file>
:  File to write federation certificates (PEM format)`,
		Flags: []cli.Flag{
			tokenFlag,
			flags.Force,
		},
	}
}

func rootsAction(ctx *cli.Context) error {
	return rootsAndFederationFlow(ctx, rootsFlow)
}

func federationAction(ctx *cli.Context) error {
	return rootsAndFederationFlow(ctx, federationFlow)
}

func getMTLSTransport(client *ca.Client, token string) (*http.Transport, error) {
	// Create a certificate for temporal use
	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return nil, err
	}
	sign, err := client.Sign(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return client.Transport(ctx, sign, pk)
}

func rootsAndFederationFlow(ctx *cli.Context, typ flowType) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	token := ctx.String("token")
	if len(token) == 0 {
		errs.RequiredFlag(ctx, "token")
	}

	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}
	var claims tokenClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return errors.Wrap(err, "error parsing flag '--token'")
	}

	// Prepare client for bootstrap or provisioning tokens
	var caURL string
	var options []ca.ClientOption
	if len(claims.SHA) > 0 && len(claims.Audience) > 0 && strings.HasPrefix(strings.ToLower(claims.Audience[0]), "http") {
		caURL = claims.Audience[0]
		options = append(options, ca.WithRootSHA256(claims.SHA))
	} else {
		caURL = ctx.String("ca-url")
		if len(caURL) == 0 {
			return errs.RequiredFlag(ctx, "ca-url")
		}
		root := ctx.String("root")
		if len(root) == 0 {
			root = pki.GetRootCAPath()
			if _, err := os.Stat(root); err != nil {
				return errs.RequiredFlag(ctx, "root")
			}
		}
		options = append(options, ca.WithRootFile(root))
	}

	ui.PrintSelected("CA", caURL)
	client, err := ca.NewClient(caURL, options...)
	if err != nil {
		return err
	}

	tr, err := getMTLSTransport(client, token)
	if err != nil {
		return err
	}

	var certs []api.Certificate
	switch typ {
	case rootsFlow:
		roots, err := client.Roots(tr)
		if err != nil {
			return err
		}
		certs = roots.Certificates
	case federationFlow:
		federation, err := client.Federation(tr)
		if err != nil {
			return err
		}
		certs = federation.Certificates
	default:
		return errors.New("unknown flow type: this should not happen")
	}

	var data []byte
	for _, cert := range certs {
		block, err := pemutil.Serialize(cert.Certificate)
		if err != nil {
			return err
		}
		data = append(data, pem.EncodeToMemory(block)...)
	}

	outFile := ctx.Args().Get(0)
	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return err
	}

	switch typ {
	case rootsFlow:
		ui.Printf("The root certificate bundle has been saved in %s.\n", outFile)
	case federationFlow:
		ui.Printf("The federation certificate bundle has been saved in %s.\n", outFile)
	default:
		return errors.New("unknown flow type: this should not happen")
	}

	return nil
}
