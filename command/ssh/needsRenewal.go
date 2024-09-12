package ssh

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils"
)

const defaultPercentUsedThreshold = 66

func needsRenewalCommand() cli.Command {
	return cli.Command{
		Name:   "needs-renewal",
		Action: cli.ActionFunc(needsRenewalAction),
		Usage:  `Check if an SSH certificate needs to be renewed`,
		UsageText: `**step ssh needs-renewal** <crt-file>
[**--expires-in**=<percent|duration>] [**--verbose**]`,
		Description: `**step ssh needs-renewal** returns '0' if the SSH certificate needs
to be renewed based on it's remaining lifetime. Returns '1' if the SSH
certificate is within it's validity lifetime bounds and does not need to be
renewed. By default, an SSH certificate "needs renewal" when it has
passed 66% (default threshold) of it's allotted lifetime. This threshold can be
adjusted using the '--expires-in' flag.

## POSITIONAL ARGUMENTS

<cert-file>
:  The path to an SSH certificate.

## EXIT CODES

This command returns '0' if the SSH certificate needs renewal, '1' if the
SSH certificate does not need renewal, '2' if the SSH certificate file does not
exist, and '255' for any other error.

## EXAMPLES

Check if an SSH certificate needs renewal using the default threshold (66%):
'''
$ step ssh needs-renewal ./ssh_host_ed25519_key.pub
'''

Check if certificate will expire within a given duration:
'''
$ step ssh needs-renewal ./ssh_host_ed25519_key.pub --expires-in 1h15m
'''

Check if an SSH certificate has passed 75 percent of it's lifetime:
'''
$ step certificate needs-renewal ./ssh_host_ed25519_key.pub --expires-in 75%
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "expires-in",
				Usage: `Check if the certificate expires within the given time window
using <percent|duration>. If using <percent>, the input must be followed by a "%"
character. If using <duration>, the input must be a sequence of decimal numbers,
each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.BoolFlag{
				Name:  "verbose, v",
				Usage: `Print human readable affirmation if certificate requires renewal.`,
			},
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return errs.NewExitError(errors.Wrap(err, "too many arguments"), 255)
	}

	var name string
	switch ctx.NArg() {
	case 0:
		name = "-"
	case 1:
		name = ctx.Args().First()
	default:
		return errs.NewExitError(errors.Errorf("too many arguments"), 255)
	}

	var (
		expiresIn = ctx.String("expires-in")
		isVerbose = ctx.Bool("verbose")
	)

	if name != "-" {
		_, err := os.Stat(name)
		switch {
		case os.IsNotExist(err):
			return errs.NewExitError(err, 2)
		case err != nil:
			return errs.NewExitError(err, 255)
		}
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return errs.NewExitError(err, 255)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return errs.NewExitError(errors.Wrap(err, "error parsing ssh certificate"), 255)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errs.NewExitError(errors.Errorf("error decoding ssh certificate: %T is not a *ssh.Certificate", pub), 255)
	}
	inspect, err := sshutil.InspectCertificate(cert)
	if err != nil {
		return errs.NewExitError(err, 255)
	}

	var (
		percentThreshold  int
		duration          time.Duration
		isPercent         = expiresIn == "" || strings.HasSuffix(expiresIn, "%")
		remainingValidity = time.Until(inspect.ValidBefore)
	)

	if isPercent {
		if expiresIn == "" {
			percentThreshold = defaultPercentUsedThreshold
		} else {
			percentThreshold, err = strconv.Atoi(strings.TrimSuffix(expiresIn, "%"))
			if err != nil {
				return errs.NewExitError(errs.InvalidFlagValue(ctx, "expires-in", expiresIn, ""), 255)
			}

			if percentThreshold > 100 || percentThreshold < 0 {
				return errs.NewExitError(errs.InvalidFlagValueMsg(ctx, "expires-in", expiresIn, "value must be in range 0-100%"), 255)
			}
		}

		totalValidity := inspect.ValidBefore.Sub(inspect.ValidAfter)
		percentUsed := (1 - remainingValidity.Minutes()/totalValidity.Minutes()) * 100

		if int(percentUsed) >= percentThreshold {
			return isVerboseExit(true, isVerbose)
		}
	} else {
		duration, err = time.ParseDuration(expiresIn)
		if err != nil {
			return errs.NewExitError(errs.InvalidFlagValue(ctx, "expires-in", expiresIn, ""), 255)
		}
		if duration >= remainingValidity {
			return isVerboseExit(true, isVerbose)
		}
	}

	return isVerboseExit(false, isVerbose)
}

func isVerboseExit(needsRenewal, isVerbose bool) error {
	if needsRenewal {
		if isVerbose {
			fmt.Println("certificate needs renewal")
		}
		return nil
	}
	return errs.NewExitError(errors.Errorf("certificate does not need renewal"), 1)
}
