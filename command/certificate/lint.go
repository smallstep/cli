package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	zx509 "github.com/smallstep/zcrypto/x509"
	"github.com/smallstep/zlint"
	"github.com/urfave/cli"
)

func lintCommand() cli.Command {
	return cli.Command{
		Name:      "lint",
		Action:    cli.ActionFunc(lintAction),
		Usage:     `lint certificate details`,
		UsageText: `**step certificate lint** <crt_file> [**--roots**=<root-bundle>]`,
		Description: `**step certificate lint** checks a certificate for common
errors and outputs the result in JSON format.

## POSITIONAL ARGUMENTS

<crt_file>
:  Path to a certificate or certificate signing request (CSR) to lint.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

'''
$ step certificate lint ./certificate.crt
'''

Lint a remote certificate (using the default root certificate bundle to verify the server):

'''
$ step certificate lint https://smallstep.com
'''

Lint a remote certificate using a custom root certificate to verify the server:

'''
$ step certificate lint https://smallstep.com --roots ./certificate.crt
'''

Lint a remote certificate using a custom list of root certificates to verify the server:

'''
$ step certificate lint https://smallstep.com \
--roots "./certificate.crt,./certificate2.crt,/certificate3.crt"
'''

Lint a remote certificate using a custom directory of root certificates to verify the server:

'''
$ step certificate lint https://smallstep.com --roots "./path/to/certificates/"
'''
`,
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
		},
	}
}

func lintAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crtFile = ctx.Args().Get(0)
		block   *pem.Block
	)
	if strings.HasPrefix(crtFile, "https://") {
		var (
			err     error
			rootCAs *x509.CertPool
		)
		if roots := ctx.String("roots"); roots != "" {
			rootCAs, err = x509util.ReadCertPool(roots)
			if err != nil {
				errors.Wrapf(err, "failure to load root certificate pool from input path '%s'", roots)
			}
		}
		addr := strings.TrimPrefix(crtFile, "https://")
		if !strings.Contains(addr, ":") {
			addr += ":443"
		}
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: rootCAs})
		if err != nil {
			return errors.Wrapf(err, "failed to connect")
		}
		conn.Close()
		crt := conn.ConnectionState().PeerCertificates[0]
		block = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}
	} else {
		crtBytes, err := ioutil.ReadFile(crtFile)
		if err != nil {
			return errs.FileError(err, crtFile)
		}
		block, _ = pem.Decode(crtBytes)
		if block == nil {
			return errors.Errorf("could not parse certificate file '%s'", crtFile)
		}
	}

	zcrt, err := zx509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	zlintResult := zlint.LintCertificate(zcrt)
	b, err := json.MarshalIndent(struct {
		*zlint.ResultSet
	}{zlintResult}, "", " ")
	if err != nil {
		return errors.WithStack(err)
	}
	os.Stdout.Write(b)

	return nil
}
