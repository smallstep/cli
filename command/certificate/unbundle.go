package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/fileutil"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func unbundleCommand() cli.Command {
	return cli.Command{
		Name:      "unbundle",
		Action:    command.ActionFunc(unbundleAction),
		Usage:     `split a bundle of certificates into its leaf and intermediates`,
		UsageText: `**step certificate unbundle** <crt-file> [**--leaf**] [**--intermediate**] [**--out**=<file>]`,
		Description: `**step certificate unbundle** splits a certificate bundle into the leaf
certificate and its intermediates. It's the inverse of **step certificate bundle**.

The first certificate in the bundle is treated as the leaf; everything after it is
treated as the intermediate chain. Pass --leaf or --intermediate to pick which part
to output. Without --out the result is printed to STDOUT, otherwise it's written to
the given file.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate bundle. A hyphen ("-") indicates STDIN.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Print the leaf certificate from a bundle:
'''
$ step certificate unbundle --leaf bundle.crt
'''

Print the intermediate chain from a bundle:
'''
$ step certificate unbundle --intermediate bundle.crt
'''

Write the leaf certificate to a file:
'''
$ step certificate unbundle --leaf --out leaf.crt bundle.crt
'''

Write the intermediate chain to a file:
'''
$ step certificate unbundle --intermediate --out intermediate.crt bundle.crt
'''
`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "leaf",
				Usage: `Output the leaf (first) certificate in the bundle.`,
			},
			cli.BoolFlag{
				Name:  "intermediate",
				Usage: `Output the intermediate certificate chain (everything after the leaf).`,
			},
			cli.StringFlag{
				Name:  "out",
				Usage: `Path to write the selected certificate(s). Defaults to STDOUT.`,
			},
			flags.Force,
		},
	}
}

func unbundleAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	leaf := ctx.Bool("leaf")
	intermediate := ctx.Bool("intermediate")
	switch {
	case leaf && intermediate:
		return errs.IncompatibleFlagWithFlag(ctx, "leaf", "intermediate")
	case !leaf && !intermediate:
		return errs.RequiredOrFlag(ctx, "leaf", "intermediate")
	}

	crtFile := ctx.Args().First()
	b, err := utils.ReadFile(crtFile)
	if err != nil {
		return errs.FileError(err, crtFile)
	}

	certs, err := pemutil.ParseCertificateBundle(b)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", crtFile)
	}

	var selected []*x509.Certificate
	if leaf {
		selected = certs[:1]
	} else {
		selected = certs[1:]
		if len(selected) == 0 {
			return errors.Errorf("%s does not contain any intermediate certificates", crtFile)
		}
	}

	var buf bytes.Buffer
	for _, crt := range selected {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}); err != nil {
			return errors.Wrap(err, "error encoding certificate")
		}
	}

	out := ctx.String("out")
	if out == "" {
		os.Stdout.Write(buf.Bytes())
		return nil
	}

	if err := fileutil.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		return err
	}
	ui.Printf("Your certificate has been saved in %s.\n", out)
	return nil
}
