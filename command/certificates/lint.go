package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	stepx509 "github.com/smallstep/cli/crypto/certificates/x509"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint"
)

func lintCommand() cli.Command {
	return cli.Command{
		Name:      "lint",
		Action:    cli.ActionFunc(lintAction),
		Usage:     `lint certificate details.`,
		UsageText: `step certificates lint CRT_FILE`,
		Description: `UPDATE ME

  POSITIONAL ARGUMENTS
    CRT_FILE
      The path to a certificate or certificate signing request (CSR) to inspect.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "roots",
				Usage: `Root certificate(s) to use in request to obtain remote server certificate.

    ROOTS is a string containing a (FILE | LIST of FILES | DIRECTORY) defined in one of the following ways:
      FILE
        Relative or full path to a file. All certificates in the file will be used for path validation.
      LIST of Files
        Comma-separated list of relative or full file paths. Every PEM encoded certificate
        from each file will be used for path validation.
      DIRECTORY
        Relative or full path to a directory. Every PEM encoded certificate from each file
        in the directory will be used for path validation.`,
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
			rootCAs, err = stepx509.ReadCertPool(roots)
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
