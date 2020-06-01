package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:   "verify",
		Action: cli.ActionFunc(verifyAction),
		Usage:  `verify a certificate`,
		UsageText: `**step certificate verify** <crt_file> [**--host**=<host>]
[**--roots**=<root-bundle>] [**--servername**=<servername>]`,
		Description: `**step certificate verify** executes the certificate path
validation algorithm for x.509 certificates defined in RFC 5280. If the
certificate is valid this command will return '0'. If validation fails, or if
an error occurs, this command will produce a non-zero return value.

## POSITIONAL ARGUMENTS

<crt_file>
: The path to a certificate to validate.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Verify a certificate using your operating system's default root certificate bundle:

'''
$ step certificate verify ./certificate.crt
'''

Verify a remote certificate using your operating system's default root certificate bundle:

'''
$ step certificate verify https://smallstep.com
'''

Verify a certificate using a custom root certificate for path validation:

'''
$ step certificate verify ./certificate.crt --roots ./root-certificate.crt
'''

Verify a certificate using a custom list of root certificates for path validation:

'''
$ step certificate verify ./certificate.crt \
--roots "./root-certificate.crt,./root-certificate2.crt,/root-certificate3.crt"
'''

Verify a certificate using a custom directory of root certificates for path validation:

'''
$ step certificate verify ./certificate.crt --roots "./path/to/root-certificates/"
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "host",
				Usage: `Check whether the certificate is for the specified host.`,
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

func verifyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crtFile          = ctx.Args().Get(0)
		host             = ctx.String("host")
		serverName       = ctx.String("servername")
		roots            = ctx.String("roots")
		intermediatePool = x509.NewCertPool()
		rootPool         *x509.CertPool
		cert             *x509.Certificate
	)

	if addr, isURL, err := trimURL(crtFile); err != nil {
		return err
	} else if isURL {
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			return err
		}
		cert = peerCertificates[0]
		for _, pc := range peerCertificates {
			intermediatePool.AddCert(pc)
		}
	} else {
		crtBytes, err := ioutil.ReadFile(crtFile)
		if err != nil {
			return errs.FileError(err, crtFile)
		}

		var (
			ipems []byte
			block *pem.Block
		)
		// The first certificate PEM in the file is our leaf Certificate.
		// Any certificate after the first is added to the list of Intermediate
		// certificates used for path validation.
		for len(crtBytes) > 0 {
			block, crtBytes = pem.Decode(crtBytes)
			if block == nil {
				return errors.Errorf("%s contains an invalid PEM block", crtFile)
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if cert == nil {
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					return errors.WithStack(err)
				}
			} else {
				ipems = append(ipems, pem.EncodeToMemory(block)...)
			}
		}
		if cert == nil {
			return errors.Errorf("%s contains no PEM certificate blocks", crtFile)
		}
		if len(ipems) > 0 && !intermediatePool.AppendCertsFromPEM(ipems) {
			return errors.Errorf("failure creating intermediate list from certificate '%s'", crtFile)
		}
	}

	if roots != "" {
		var err error
		rootPool, err = x509util.ReadCertPool(roots)
		if err != nil {
			errors.Wrapf(err, "failure to load root certificate pool from input path '%s'", roots)
		}
	}

	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	if _, err := cert.Verify(opts); err != nil {
		return errors.Wrapf(err, "failed to verify certificate")
	}

	return nil
}
