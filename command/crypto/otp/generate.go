package otp

import (
	"bytes"
	"fmt"
	"image/png"

	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func generateCommand() cli.Command {
	return cli.Command{
		Name:        "generate",
		Action:      cli.ActionFunc(generateAction),
		Usage:       "one-time password",
		UsageText:   `step crypto otp generate`,
		Description: `The 'step crypto otp generate' command does TOTP and HTOP`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "issuer, iss",
				Usage: `Name of the issuing organization (e.g., smallstep.com)`,
			},
			cli.StringFlag{
				Name: "account",
				Usage: `Name of the user's account (e.g., a username or email
address)`,
			},
			cli.IntFlag{
				Name: "period",
				Usage: `Number of seconds a TOTP hash is valid. Defaults to 30
seconds.`,
				Value: 30,
			},
			cli.IntFlag{
				Name:  "length, digits",
				Usage: `Length of one-time passwords. Defaults to 6.`,
				Value: 6,
			},
			cli.IntFlag{
				Name:  "secret-size",
				Usage: `Size of generated TOTP secret. Defaults to 20.`,
				Value: 20,
			},
			cli.StringFlag{
				Name: "alg, algorithm",
				Usage: `Algorithm to use for HMAC. Defaults to SHA1. Must be
one of: SHA1, SHA256, SHA512`,
				Value: "SHA1",
			},
			cli.BoolFlag{
				Name: "url",
				Usage: `Output a TOTP Key URI. See
https://github.com/google/google-authenticator/wiki/Key-Uri-Format`,
			},
			cli.StringFlag{
				Name:  "qr",
				Usage: `Write a QR code to the specified path`,
			},
		},
	}
}

func generateAction(ctx *cli.Context) error {
	switch {
	case len(ctx.String("issuer")) == 0:
		return errs.RequiredFlag(ctx, "issuer")
	case len(ctx.String("account")) == 0:
		return errs.RequiredFlag(ctx, "account")
	}

	key, err := generate(ctx)
	if err != nil {
		return err
	}

	if ctx.IsSet("qr") {
		filename := ctx.String("qr")

		// Convert TOTP key into a PNG
		var buf bytes.Buffer
		img, err := key.Image(200, 200)
		if err != nil {
			return err
		}
		png.Encode(&buf, img)
		if err := utils.WriteFile(filename, buf.Bytes(), 0644); err != nil {
			return errs.FileError(err, filename)
		}
	}

	if ctx.Bool("url") {
		fmt.Println(key.String())
	} else {
		fmt.Println(key.Secret())
	}

	return nil
}
