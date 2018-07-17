package otp

import (
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

// Command returns the cli.Command for jwt and related subcommands.
func Command() cli.Command {
	return cli.Command{
		Name:        "otp",
		Usage:       "generate and verify one-time passwords",
		UsageText:   "step crypto otp SUBCOMMAND [SUBCOMMAND_ARGUMENTS] [GLOBAL_FLAGS] [SUBCOMMAND_FLAGS]",
		Description: `Implements TOTP and HOTP one-time passwords (mention RFCs)`,
		Subcommands: cli.Commands{
			generateCommand(),
			verifyCommand(),
		},
	}
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
