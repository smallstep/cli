package certificate

import (
	"crypto/tls"
	realx509 "crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certinfo"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	x509 "github.com/smallstep/cli/pkg/x509"
	"github.com/smallstep/cli/utils"
	zx509 "github.com/smallstep/zcrypto/x509"
	"github.com/urfave/cli"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:   "inspect",
		Action: cli.ActionFunc(inspectAction),
		Usage:  `print certificate or CSR details in human readable format`,
		UsageText: `**step certificate inspect** <crt_file> [**--bundle**]
[**--format**=<format>] [**--roots**=<root-bundle>]`,
		Description: `**step certificate inspect** prints the details of a certificate
or CSR in a human readable format. Output from the inspect command is printed to
STDERR instead of STDOUT unless. This is an intentional barrier to accidental
misuse: scripts should never rely on the contents of an unvalidated certificate.
For scripting purposes, use **step certificate verify**.

If crt_file contains multiple certificates (i.e., it is a certificate "bundle")
the first certificate in the bundle will be output. Pass the --bundle option to
print all certificates in the order in which they appear in the bundle.

## POSITIONAL ARGUMENTS

<crt_file>
:  Path to a certificate or certificate signing request (CSR) to inspect. A hyphen ("-") indicates STDIN as <crt_file>.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Inspect a local certificate (default to text format):

'''
$ step certificate inspect ./certificate.crt
'''

Inspect a local certificate bundle (default to text format):

'''
$ step certificate inspect ./certificate-bundle.crt --bundle
'''

Inspect a local certificate in json format:

'''
$ step certificate inspect ./certificate.crt --format json
'''

Inspect a local certificate bundle in json format:

'''
$ step certificate inspect ./certificate.crt --format json --bundle
'''

Inspect a remote certificate (using the default root certificate bundle to verify the server):

'''
$ step certificate inspect https://smallstep.com
'''

Inspect an invalid remote certificate:

'''
$ step certificate inspect --insecure https://expired.badssl.com
'''

Inspect a remote certificate chain (using the default root certificate bundle to verify the server):

'''
$ step certificate inspect https://google.com --bundle
'''

Inspect a remote certificate using a custom root certificate to verify the server:

'''
$ step certificate inspect https://smallstep.com --roots ./root-ca.crt
'''

Inspect a remote certificate using a custom list of root certificates to verify the server:

'''
$ step certificate inspect https://smallstep.com \
--roots "./root-ca.crt,./root-ca2.crt,/root-ca3.crt"
'''

Inspect a remote certificate using a custom directory of root certificates to verify the server:

'''
$ step certificate inspect https://smallstep.com \
--roots "./path/to/root/certificates/"
'''

Inspect a remote certificate chain in json format using a custom directory of
root certificates to verify the server:

'''
$ step certificate inspect https://google.com --format json \
--roots "./path/to/root/certificates/" --bundle
'''

Inspect a local CSR in text format (default):

'''
$ step certificate inspect foo.csr
'''

Inspect a local CSR in json:

'''
$ step certificate inspect foo.csr --format json
'''
`,

		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format",
				Value: "text",
				Usage: `The output format for printing the introspection details.

: <format> is a string and must be one of:

    **text**
    :  Print output in unstructured text suitable for a human to read.

    **json**
    :  Print output in JSON format.`,
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
				Name: `bundle`,
				Usage: `Print all certificates in the order in which they appear in the bundle.
If the output format is 'json' then output a list of certificates, even if
the bundle only contains one certificate. This flag will result in an error
if the input bundle includes any PEM that does not have type CERTIFICATE.`,
			},
			cli.BoolFlag{
				Name: "insecure",
				Usage: `Use an insecure client to retrieve a remote peer certificate. Useful for
debugging invalid certificates remotely.`,
			},
		},
	}
}

func inspectAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crtFile  = ctx.Args().Get(0)
		bundle   = ctx.Bool("bundle")
		format   = ctx.String("format")
		roots    = ctx.String("roots")
		insecure = ctx.Bool("insecure")
	)

	if format != "text" && format != "json" {
		return errs.InvalidFlagValue(ctx, "format", format, "text, json")
	}

	if bundle {
		var blocks []*pem.Block
		if strings.HasPrefix(crtFile, "https://") {
			peerCertificates, err := getPeerCertificates(crtFile, roots, insecure)
			if err != nil {
				return errors.WithStack(err)
			}
			for _, crt := range peerCertificates {
				blocks = append(blocks, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: crt.Raw,
				})
			}
		} else {
			crtBytes, err := utils.ReadFile(crtFile)
			if err != nil {
				return errs.FileError(err, crtFile)
			}

			var block *pem.Block
			for len(crtBytes) > 0 {
				block, crtBytes = pem.Decode(crtBytes)
				if block == nil {
					return errors.Errorf("%s contains an invalid PEM block", crtFile)
				}
				if block.Type != "CERTIFICATE" {
					return errors.Errorf("certificate bundle %s contains an "+
						"unexpected PEM block of type %s\n\n  expected type: "+
						"CERTIFICATE", crtFile, block.Type)
				}
				blocks = append(blocks, block)
			}
		}

		switch format {
		case "text":
			for _, block := range blocks {
				crt, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return errors.WithStack(err)
				}
				result, err := certinfo.CertificateText(crt)
				if err != nil {
					return errors.WithStack(err)
				}
				fmt.Print(result)
			}
		case "json":
			var zcrts []*zx509.Certificate
			for _, block := range blocks {
				zcrt, err := zx509.ParseCertificate(block.Bytes)
				if err != nil {
					return errors.WithStack(err)
				}
				zcrts = append(zcrts, zcrt)
			}
			b, err := json.MarshalIndent(zcrts, "", "  ")
			if err != nil {
				return errors.WithStack(err)
			}
			os.Stdout.Write(b)
		default:
			return errs.InvalidFlagValue(ctx, "format", format, "text, json")
		}
	} else { // Only inspect the leaf certificate.
		var block *pem.Block

		if strings.HasPrefix(crtFile, "https://") {
			peerCertificates, err := getPeerCertificates(crtFile, roots, insecure)
			if err != nil {
				return errors.WithStack(err)
			}
			block = &pem.Block{
				Type: "CERTIFICATE",
				// leaf certificate should be first in PeerCertificates returned
				// by tls.Conn.
				Bytes: peerCertificates[0].Raw,
			}
		} else {
			crtBytes, err := utils.ReadFile(crtFile)
			if err != nil {
				return errs.FileError(err, crtFile)
			}

			// leaf certificate should be the first in the file
			block, _ = pem.Decode(crtBytes)
			if block == nil {
				return errors.Errorf("%s contains an invalid PEM block", crtFile)
			}
		}
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
				return errs.InvalidFlagValue(ctx, "format", format, "text, json")
			}
		case "CERTIFICATE REQUEST":
			switch format {
			case "text":
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				if err != nil {
					return errors.WithStack(err)
				}
				result, err := certinfo.CertificateRequestText(csr)
				if err != nil {
					return errors.WithStack(err)
				}
				fmt.Print(result)
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
				return errs.InvalidFlagValue(ctx, "format", format, "text, json")
			}
		default:
			return errors.Errorf("Invalid PEM type in %s. Expected [CERTIFICATE|CSR] but got %s)", crtFile, block.Type)
		}
	}

	return nil
}

func getPeerCertificates(url, roots string, insecure bool) ([]*realx509.Certificate, error) {
	var (
		err     error
		rootCAs *realx509.CertPool
	)
	if roots != "" {
		rootCAs, err = x509util.ReadCertPool(roots)
		if err != nil {
			return nil, errors.Wrapf(err, "failure to load root certificate pool from input path '%s'", roots)
		}
	}
	addr := strings.TrimPrefix(url, "https://")
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	tlsConfig := &tls.Config{RootCAs: rootCAs}
	if insecure {
		tlsConfig.InsecureSkipVerify = true
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect")
	}
	conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}
