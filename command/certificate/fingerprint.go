package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func fingerprintCommand() cli.Command {
	return cli.Command{
		Name:      "fingerprint",
		Action:    cli.ActionFunc(fingerprintAction),
		Usage:     "print the fingerprint of a certificate",
		UsageText: `**step certificate fingerprint** <crt-file>`,
		Description: `**step certificate fingerprint** reads a certificate and prints to STDOUT the
certificate SHA256 of the raw certificate.

## POSITIONAL ARGUMENTS

<crt-file>
:  A certificate PEM file, usually the root certificate.

## EXAMPLES

Get the fingerprint for a root certificate:
'''
$ step certificate fingerprint /path/to/root_ca.crt
0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''

Get the fingerprint for a remote certificate:
'''
$ step certificate fingerprint https://smallstep.com
0d7d3834cf187726cf331c40a31aa7ef6b29ba4df601416c9788f6ee01058cf3
'''`,
		Flags: []cli.Flag{
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
				Name: "insecure",
				Usage: `Use an insecure client to retrieve a remote peer certificate. Useful for
debugging invalid certificates remotely.`,
			},
		},
	}
}

func fingerprintAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crt      *x509.Certificate
		err      error
		roots    = ctx.String("roots")
		insecure = ctx.Bool("insecure")
		crtFile  = ctx.Args().First()
	)

	if _, addr, isURL := trimURLPrefix(crtFile); isURL {
		peerCertificates, err := getPeerCertificates(addr, roots, insecure)
		if err != nil {
			return err
		}
		crt = peerCertificates[0]
	} else {
		crt, err = pemutil.ReadCertificate(crtFile)
		if err != nil {
			return err
		}
	}

	sum := sha256.Sum256(crt.Raw)
	fmt.Println(strings.ToLower(hex.EncodeToString(sum[:])))
	return nil
}
