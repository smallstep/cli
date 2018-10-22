package certificate

import (
	"crypto/sha256"
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
$ step certificate fingerprint root_ca.crt
'''`,
	}
}

func fingerprintAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	crt, err := pemutil.ReadCertificate(ctx.Args().First())
	if err != nil {
		return err
	}

	sum := sha256.Sum256(crt.Raw)
	fmt.Println(strings.ToLower(hex.EncodeToString(sum[:])))
	return nil
}
