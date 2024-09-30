package otp

import (
	"bytes"
	"fmt"
	"image/png"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func generateCommand() cli.Command {
	return cli.Command{
		Name:   "generate",
		Action: command.ActionFunc(generateAction),
		Usage:  "generate a one-time password",
		UsageText: `**step crypto otp generate** [**--issuer**=<name>]
[**--account**=<user-name>] [**--period**=<seconds>] [**--length**=<size>]
[**--alg**=<alg>] [**--url**] [**--qr**]`,
		Description: `**step crypto otp generate** does TOTP and HTOP`,
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
			flags.Force,
		},
	}
}

func generateAction(ctx *cli.Context) error {
	switch {
	case ctx.String("issuer") == "":
		return errs.RequiredFlag(ctx, "issuer")
	case ctx.String("account") == "":
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

func algFromString(ctx *cli.Context, alg string) (otp.Algorithm, error) {
	switch strings.ToUpper(alg) {
	case "SHA1":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, errs.InvalidFlagValue(ctx, "alg", alg, "SHA1, SHA256, or SHA512")
	}
}

func generate(ctx *cli.Context) (*otp.Key, error) {
	alg, err := algFromString(ctx, ctx.String("alg"))
	if err != nil {
		return nil, err
	}
	return totp.Generate(totp.GenerateOpts{
		Issuer:      ctx.String("issuer"),
		AccountName: ctx.String("account"),
		Period:      uint(ctx.Int("period")),
		SecretSize:  uint(ctx.Int("secret-size")),
		Digits:      otp.Digits(ctx.Int("length")),
		Algorithm:   alg,
	})
}
