package certificate

import (
	"crypto/x509"
	"strconv"
	"strings"
	"time"

	"github.com/smallstep/cli/flags"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

const defaultPercentUsedThreshold = 66

func needsRenewalCommand() cli.Command {
	return cli.Command{
		Name:   "needs-renewal",
		Action: cli.ActionFunc(needsRenewalAction),
		Usage:  `Check if a certificate needs to be renewed`,
		UsageText: `**step certificate needs-renewal** <cert_file or host_name>
[**--expires-in**=<duration>] [**--roots**=<root-bundle>] [**--servername**=<servername>]`,
		Description: `**step certificate needs-renewal** returns '0' if the certificate needs
to be renewed based on it's remaining lifetime. Returns '1' the certificate is
within it's validity lifetime bounds and does not need to be renewed. Returns
'255' for any other error. By default, a certificate "needs renewal" when it has
passed 66% (default threshold) of it's allotted lifetime. This threshold can be
adjusted using the '--expires-in' flag.

## POSITIONAL ARGUMENTS

<cert_file or hostname>
:  The path to a certificate OR a hostname with protocol prefix.

## EXIT CODES

This command returns '0' if the certificate needs renewal, '1' if the
certificate does not need renewal, and '255' for any error.

## EXAMPLES

Check certificate for renewal using custom directory:
'''
$ step certificate needs-renewal ./certificate.crt
'''

Check certificate for renewal using a hostname:
'''
$ step certificate needs-renewal https://smallstep.com
'''

Check if certificate will expire within a given duration:
'''
$ step certificate needs-renewal ./certificate.crt --expires-in 1h15m
'''

Check if certificate from hostname will expire within a given duration:
'''
$ step certificate needs-renewal https://smallstep.com --expires-in 1h15m
'''

Check if certificate has passed 75 percent of it's lifetime:
'''
$ step certificate needs-renewal ./certificate.crt --expires-in 75%
'''

Check if certificate from a hostname has passed 75 percent of it's lifetime:
'''
$ step certificate needs-renewal https://smallstep.com --expires-in 75%
'''

Check a remote certificate using a custom root certificate:
'''
$ step certificate needs-renewal https://smallstep.com --roots ./root-ca.crt
'''

Check a remote certificate using a custom list of root certificates:
'''
$ step certificate needs-renewal https://smallstep.com \
--roots "./root-ca.crt,./root-ca2.crt,/root-ca3.crt"
'''

Check a remote certificate using a custom directory of root certificates:
'''
$ step certificate needs-renewal https://smallstep.com \
--roots "./path/to/root/certificates/"
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
			cli.StringFlag{
				Name: "roots",
				Usage: `Root certificate(s) that will be used to verify the
authenticity of the remote server.

: <roots> is a case-sensitive string and may be one of:

    **file**
	:  Relative or full path to a file. All certificates in the file will be used for path validation.

    **list of files**
	:  Comma-separated list of relative or full file paths. Every PEM encoded certificate from each file will be used for path validation.

    **directory**
	:  Relative or full path to a directory. Every PEM encoded certificate from each file in the directory will be used for path validation.`,
			},
			flags.ServerName,
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		err        error
		crtFile    = ctx.Args().Get(0)
		expiresIn  = ctx.String("expires-in")
		roots      = ctx.String("roots")
		serverName = ctx.String("servername")
	)

	var certs []*x509.Certificate
	if addr, isURL, err := trimURL(crtFile); err != nil {
		return errs.NewExitError(err, 255)
	} else if isURL {
		certs, err = getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			return errs.NewExitError(err, 255)
		}
	} else {
		certs, err = pemutil.ReadCertificateBundle(crtFile)
		if err != nil {
			return errs.NewExitError(err, 255)
		}
	}

	var (
		percentThreshold int
		duration         time.Duration
		isPercent        = expiresIn == "" || strings.HasSuffix(expiresIn, "%")
	)

	if isPercent {
		if expiresIn == "" {
			percentThreshold = defaultPercentUsedThreshold
		} else {
			percentThreshold, err = strconv.Atoi(strings.TrimSuffix(expiresIn, "%"))
			if err != nil {
				return errs.NewExitError(errs.InvalidFlagValue(ctx, "expires-in", expiresIn, ""), 255)
			}
		}
		if percentThreshold > 100 || percentThreshold < 0 {
			return errs.NewExitError(errs.InvalidFlagValueMsg(ctx, "expires-in", expiresIn, "value must be in range 0-100%"), 255)
		}
	} else {
		duration, err = time.ParseDuration(expiresIn)
		if err != nil {
			return errs.NewExitError(errs.InvalidFlagValue(ctx, "expires-in", expiresIn, ""), 255)
		}
	}

	for _, cert := range certs {

		remainingValidity := time.Until(cert.NotAfter)

		if isPercent {
			totalValidity := cert.NotAfter.Sub(cert.NotBefore)
			percentUsed := (1 - remainingValidity.Minutes()/totalValidity.Minutes()) * 100

			if int(percentUsed) >= percentThreshold {
				return nil
			}
		} else {
			if duration >= remainingValidity {
				return nil
			}
		}
	}

	return errs.NewExitError(errors.Errorf("certificate does not need renewal"), 1)
}
