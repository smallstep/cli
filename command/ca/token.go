package ca

import (
	"fmt"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

const defaultSignatureAlgorithm = "ES256"

func newTokenCommand() cli.Command {
	return cli.Command{
		Name:   "new-token",
		Action: cli.ActionFunc(newTokenAction),
		Usage:  "generates an OTT granting access to the CA",
		UsageText: `**step ca new-token** <hostname>
		[**--ca**=<file>] [**--ca-url**=<uri>] 
		[**--password-file**=<file>] [**--output-file**=<file>]`,
		Description: `**step ca new-token** command generates a one-time token granting access to the
certificates authority`,
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
				Name: "password-file",
				Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
			},
			cli.StringFlag{
				Name:  "output-file",
				Usage: "The destination <file> of the generated one-time token.",
			},
		},
	}
}

func newTokenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	ca := ctx.String("ca")
	caURL := ctx.String("ca-url")
	passwordFile := ctx.String("password-file")
	outputFile := ctx.String("output-file")
	subject := ctx.Args().Get(0)

	// Read OTT key
	var pemOptions []pemutil.Options
	if len(passwordFile) != 0 {
		pemOptions = append(pemOptions, pemutil.WithPasswordFile(passwordFile))
	}

	key, err := pemutil.Read(pki.GetOTTKeyPath(), pemOptions...)
	if err != nil {
		return err
	}

	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.ASCII(64)
	if err != nil {
		return err
	}

	// Generate token
	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
	}
	if len(ca) > 0 {
		tokOptions = append(tokOptions, token.WithRootCA(ca))
	}
	if len(caURL) > 0 {
		tokOptions = append(tokOptions, token.WithCA(caURL))
	}

	tok, err := provision.New(subject, tokOptions...)
	if err != nil {
		return err
	}

	token, err := tok.SignedString(defaultSignatureAlgorithm, key)
	if err != nil {
		return err
	}

	if len(outputFile) > 0 {
		return utils.WriteFile(outputFile, []byte(token), 0600)
	}
	fmt.Println(token)
	return nil
}
