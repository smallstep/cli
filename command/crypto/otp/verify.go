package otp

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: cli.ActionFunc(verifyAction),
		Usage:  "verify a one-time password",
		UsageText: `**step crypto otp verify** <secret-file>
[**--period**=<seconds>] [**--skew**=<num>] [**--length**=<size>]
[**--alg**=<alg>] [*--time**=<time|duration>]`,
		Description: `**step crypto otp verify** does TOTP and HTOP`,
		Flags: []cli.Flag{
			cli.UintFlag{
				Name: "period",
				Usage: `Number of seconds a TOTP hash is valid. Defaults to 30
seconds.`,
				Value: 30,
			},
			cli.UintFlag{
				Name: "skew",
				Usage: `Periods before or after current time to allow. Defaults
to 0. Values greater than 1 require '--insecure' flag.`,
				Value: 0,
			},
			cli.IntFlag{
				Name:  "length, digits",
				Usage: `Length of one-time passwords. Defaults to 6 digits.`,
				Value: 6,
			},
			cli.StringFlag{
				Name: "alg, algorithm",
				Usage: `Algorithm to use for HMAC. Defaults to SHA1. Must be
one of: SHA1, SHA256, SHA512`,
				Value: "SHA1",
			},
			cli.StringFlag{
				Name: "time",
				Usage: `The <time|duration> to use for TOTP validation. If a <time> is
used it is expected to be in RFC 3339 format. If a <duration> is used, it is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h". A <duration> value is added to the current time. An empty
<time|duration> defaults to "time.Now()".`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
		},
	}
}

func verifyAction(ctx *cli.Context) error {
	args := ctx.Args()
	secretFile := args.Get(0)

	b, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return errs.FileError(err, secretFile)
	}
	secret := string(b)
	if strings.HasPrefix(secret, "otpauth://") {
		url, err := otp.NewKeyFromURL(secret)
		if err != nil {
			return err
		}
		secret = url.Secret()
	}

	alg, err := algFromString(ctx, ctx.String("alg"))
	if err != nil {
		return err
	}

	var (
		ok         bool
		selectTime time.Time
	)
	if ctx.String("time") == "" {
		selectTime = time.Now()
	} else {
		selectTime, ok = flags.ParseTimeOrDuration(ctx.String("time"))
		if !ok {
			return errs.InvalidFlagValue(ctx, "time", ctx.String("time"), "")
		}
	}

	skew := ctx.Uint("skew")
	if skew > 1 && !ctx.Bool("insecure") {
		return errors.Errorf("'--skew' values greater than 1 require the '--insecure' flag")
	}

	passcode, err := utils.ReadInput("Enter Passcode")
	if err != nil {
		return errors.Wrap(err, "error reading passcode")
	}
	valid, err := totp.ValidateCustom(string(passcode), secret, selectTime, totp.ValidateOpts{
		Period:    ctx.Uint("period"),
		Skew:      skew,
		Digits:    otp.Digits(ctx.Int("length")),
		Algorithm: alg,
	})

	if err != nil {
		return errors.Wrap(err, "error while validating TOTP")
	} else if valid {
		fmt.Println("ok")
		os.Exit(0)
	} else {
		fmt.Println("fail")
		os.Exit(1)
	}
	return nil
}
