package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/grantae/certinfo"
	"github.com/pkg/errors"
	stepx509 "github.com/smallstep/cli/crypto/certificates/x509"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
	zx509 "github.com/zmap/zcrypto/x509"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:      "inspect",
		Action:    cli.ActionFunc(inspectAction),
		Usage:     `print certificate or CSR details in human readable format.`,
		UsageText: `step certificates inspect CRT_FILE [--format=FORMAT]`,
		Description: `The 'step certificates inspect' command prints the details of a certificate
or CSR in a human readable format. Output from the inspect command is printed to
STDERR instead of STDOUT unless. This is an intentional barrier to accidental
misuse: scripts should never rely on the contents of an unvalidated certificate.
For scripting purposes, use 'step certificates verify'.

  POSITIONAL ARGUMENTS
    CRT_FILE
      The path to a certificate or certificate signing request (CSR) to inspect.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format",
				Value: "text",
				Usage: `The output format for printing the introspection details.

  FORMAT must be one of:
    text
      Print output in unstructured text suitable for a human to read
    json
      Print output in JSON format`,
			},
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

func inspectAction(ctx *cli.Context) error {
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

	format := ctx.String("format")
	switch block.Type {
	case "CERTIFICATE":
		switch format {
		case "text":
			crt, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.WithStack(err)
			}
			result, err := certinfo.CertificateText(crt)
			if err != nil {
				return errors.WithStack(err)
			}
			fmt.Print(result)
		case "json":
			zcrt, err := zx509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.WithStack(err)
			}
			b, err := json.MarshalIndent(struct {
				*zx509.Certificate
			}{zcrt}, "", "  ")
			if err != nil {
				return errors.WithStack(err)
			}
			os.Stdout.Write(b)
		default:
			return errors.Errorf("invalid value for '--format'. '--format' must be "+
				"one of 'text'(default) or 'json', but got '%s'", format)
		}
	case "CSR":
		switch format {
		case "text":
			return errors.Errorf("Not implemented. Come back later :)")
		case "json":
			zcsr, err := zx509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return errors.WithStack(err)
			}
			b, err := json.MarshalIndent(struct {
				*zx509.CertificateRequest
			}{zcsr}, "", "  ")
			if err != nil {
				return errors.WithStack(err)
			}
			os.Stdout.Write(b)
		default:
			return errors.Errorf("invalid value for '--format'. '--format' must be "+
				"one of 'text'(default) or 'json', but got '%s'", format)
		}
	default:
		return errors.Errorf("Invalid PEM type in '%s'. Expected ['CERTIFICATE'|'CSR'] but got '%s')", crtFile, block.Type)
	}

	return nil
}
