package otp

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: cli.ActionFunc(verifyAction),
		Usage:  "verify a one-time password",
		UsageText: `**step crypto otp verify** [**--secret**=<file>]
[**--period**=<seconds>] [**--skew**=<num>] [**--length**=<size>]
[**--alg**=<alg>] [*--time**=<time|duration>]`,
		Description: `**step crypto otp verify** does TOTP and HTOP`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "secret",
				Usage: `The <file> containing TOTP secret.`,
			},
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
			flags.InsecureHidden,
		},
	}
}

func verifyAction(ctx *cli.Context) error {
	var (
		secret string
		// defaults
		period = uint(30)
		digits = 6
		algStr = "SHA1"
	)

	secretFile := ctx.String("secret")
	if secretFile == "" {
		args := ctx.Args()
		if len(args) == 0 {
			return errs.RequiredFlag(ctx, "secret")
		}
		secretFile = args[0]
	}
	b, err := os.ReadFile(secretFile)
	if err != nil {
		return errs.FileError(err, secretFile)
	}
	secret = string(b)
	if strings.HasPrefix(secret, "otpauth://") {
		otpKey, err := otp.NewKeyFromURL(secret)
		if err != nil {
			return errors.Wrap(err, "error parsing TOTP key from URL")
		}

		u, err := url.Parse(strings.TrimSpace(secret))
		if err != nil {
			return errors.Wrap(err, "error parsing TOTP Key URI in secret file")
		}
		q := u.Query()

		secret = otpKey.Secret()
		// period query param
		if periodStr := q.Get("period"); periodStr != "" {
			period64, err := strconv.ParseUint(periodStr, 10, 0)
			if err != nil {
				return errors.Wrap(err, "error parsing period from url")
			}
			period = uint(period64)
		}
		// digits query param
		if digitStr := q.Get("digits"); digitStr != "" {
			digits64, err := strconv.ParseInt(digitStr, 10, 0)
			if err != nil {
				return errors.Wrap(err, "error parsing period from url")
			}
			digits = int(digits64)
		}
		// algorithm query param
		algFromQuery := q.Get("algorithm")
		if algFromQuery != "" {
			algStr = algFromQuery
		}
	}

	if ctx.IsSet("period") {
		period = ctx.Uint("period")
	}
	if ctx.IsSet("digits") {
		digits = ctx.Int("digits")
	}
	if ctx.IsSet("alg") {
		algStr = ctx.String("alg")
	}
	alg, err := algFromString(ctx, algStr)
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
		Period:    period,
		Skew:      skew,
		Digits:    otp.Digits(digits),
		Algorithm: alg,
	})

	switch {
	case err != nil:
		return errors.Wrap(err, "error while validating TOTP")
	case valid:
		fmt.Println("ok")
		os.Exit(0)
	default:
		fmt.Println("fail")
		os.Exit(1)
	}
	return nil
}
