package otp

import (
	"github.com/urfave/cli"
)

// Command returns the cli.Command for jwt and related subcommands.
func Command() cli.Command {
	return cli.Command{
		Name:      "otp",
		Usage:     "generate and verify one-time passwords",
		UsageText: "step crypto otp <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto otp** command group implements TOTP and HOTP one-time passwords
(mention RFCs)

## EXAMPLES

Generate a new TOTP token and it's QR Code to scan:
'''
$ step crypto otp generate --issuer smallstep.com --account name@smallstep.com -qr smallstep.png \> smallstep.totp

$ cat smallstep.totp
55RU6WTUISKKGEYVNSSI7H6FTJWJ4IPP
'''

Scan the QR Code using Google Authenticator, Authy or a similar software and
use it to verify the TOTP token:
'''
$ step crypto otp verify --secret smallstep.totp
Enter Passcode: 614318
ok
'''`,
		Subcommands: cli.Commands{
			generateCommand(),
			verifyCommand(),
		},
	}
}
