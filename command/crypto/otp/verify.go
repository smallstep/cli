package otp

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:        "verify",
		Action:      cli.ActionFunc(verifyAction),
		Usage:       "verify a one-time password",
		UsageText:   `**step crypto otp verify**`,
		Description: `**step crypto otp verify** does TOTP and HTOP`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "secret",
				Usage: `A file containing the OTP secret`,
			},
			cli.IntFlag{
				Name: "period",
				Usage: `Number of seconds a TOTP hash is valid. Defaults to 30
seconds.`,
				Value: 30,
			},
			cli.IntFlag{
				Name: "skew",
				Usage: `Periods before or after current time to allow. Defaults
to 0. Values greater than 1 require '--insecure'`,
				Value: 0,
			},
			cli.IntFlag{
				Name:  "length digits",
				Usage: `Length of one-time passwords. Defaults to 6.`,
				Value: 6,
			},
			cli.StringFlag{
				Name: "alg algorithm",
				Usage: `Algorithm to use for HMAC. Defaults to SHA1. Must be
one of: SHA1, SHA256, SHA512`,
				Value: "SHA1",
			},
			cli.IntFlag{
				Name:  "time",
				Usage: `Time to use for TOTP calculation. Defaults to now.`,
			},
		},
	}
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return text
}

func verifyAction(ctx *cli.Context) error {
	filename := ctx.String("secret")
	if len(filename) == 0 {
		return errs.RequiredFlag(ctx, "secret")
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return errs.FileError(err, filename)
	}
	secret := string(b)

	if strings.HasPrefix(secret, "otpauth://") {
		url, err := otp.NewKeyFromURL(secret)
		if err != nil {
			return err
		}
		secret = url.Secret()
	}

	passcode := promptForPasscode()
	valid := totp.Validate(passcode, secret)
	if valid {
		fmt.Println("ok")
		os.Exit(0)
	} else {
		fmt.Println("fail")
		os.Exit(1)
	}
	return nil
}
