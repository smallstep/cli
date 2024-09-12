package certificate

import (
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
)

const defaultPercentUsedThreshold = 66

func needsRenewalCommand() cli.Command {
	return cli.Command{
		Name:   "needs-renewal",
		Action: cli.ActionFunc(needsRenewalAction),
		Usage:  `Check if a certificate needs to be renewed`,
		UsageText: `**step certificate needs-renewal** <cert-file or hostname>
[**--expires-in**=<percent|duration>] [**--bundle**] [**--verbose**]
[**--roots**=<root-bundle>] [**--servername**=<servername>]`,
		Description: `**step certificate needs-renewal** returns '0' if the certificate needs
to be renewed based on its remaining lifetime. Returns '1' the certificate is
within its validity lifetime bounds and does not need to be renewed.
By default, a certificate "needs renewal" when it has passed 66% (default
threshold) of its allotted lifetime. This threshold can be adjusted using the
'--expires-in' flag. Additionally, by default only the leaf certificate will
be checked by the command; to check each certificate in the chain use the
'--bundle' flag.

## POSITIONAL ARGUMENTS

<cert-file or hostname>
:  The path to a certificate OR a hostname with protocol prefix.

## EXIT CODES

This command returns '0' if the X509 certificate needs renewal, '1' if the
X509 certificate does not need renewal, '2' if the X509 certificate file does not
exist, and '255' for any other error.

## EXAMPLES

Check if the leaf certificate in the file certificate.crt has passed 66 percent of its validity period:
'''
$ step certificate needs-renewal ./certificate.crt
'''

Check if any certificate in the bundle has passed 66 percent of its validity period:
'''
$ step certificate needs-renewal ./certificate.crt --bundle
'''

Check if the leaf certificate provided by smallstep.com has passed 66 percent
of its vlaidity period:
'''
$ step certificate needs-renewal https://smallstep.com
'''

Check if any certificate in the bundle for smallstep.com has has passed 66 percent
of its validity period:
'''
$ step certificate needs-renewal https://smallstep.com --bundle
'''

Check if certificate.crt expires within 1 hour 15 minutes from now:
'''
$ step certificate needs-renewal ./certificate.crt --expires-in 1h15m
'''

Check if certificate for smallstep.com is expired or not:
'''
$ step certificate needs-renewal https://smallstep.com --expires-in 0s
'''

Check if certificate has passed 75 percent of its validity period:
'''
$ step certificate needs-renewal ./certificate.crt --expires-in 75%
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
			cli.BoolFlag{
				Name:  `bundle`,
				Usage: `Check all certificates in the order in which they appear in the bundle.`,
			},
			cli.BoolFlag{
				Name:  "verbose, v",
				Usage: `Print human readable affirmation if certificate requires renewal.`,
			},
			flags.ServerName,
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return errs.NewExitError(err, 255)
	}

	var (
		err        error
		certFile   = ctx.Args().Get(0)
		expiresIn  = ctx.String("expires-in")
		roots      = ctx.String("roots")
		serverName = ctx.String("servername")
		bundle     = ctx.Bool("bundle")
		isVerbose  = ctx.Bool("verbose")
	)

	var certs []*x509.Certificate
	switch addr, isURL, err := trimURL(certFile); {
	case err != nil:
		return errs.NewExitError(err, 255)
	case isURL:
		certs, err = getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			return errs.NewExitError(err, 255)
		}
	default:
		_, err = os.Stat(certFile)
		switch {
		case os.IsNotExist(err):
			return errs.NewExitError(err, 2)
		case err != nil:
			return errs.NewExitError(err, 255)
		default:
			certs, err = pemutil.ReadCertificateBundle(certFile)
			if err != nil {
				return errs.NewExitError(err, 255)
			}
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
				return isVerboseExit(true, isVerbose)
			}
		} else if duration >= remainingValidity {
			return isVerboseExit(true, isVerbose)
		}

		if !bundle {
			break
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
