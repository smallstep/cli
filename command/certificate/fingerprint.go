package certificate

import (
	"crypto"
	"crypto/x509"
	"fmt"

	//nolint:gosec // support for sha1 fingerprints
	_ "crypto/sha1"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func fingerprintCommand() cli.Command {
	return cli.Command{
		Name:   "fingerprint",
		Action: cli.ActionFunc(fingerprintAction),
		Usage:  "print the fingerprint of a certificate",
		UsageText: `**step certificate fingerprint** <crt-file>
[**--bundle**] [**--roots**=<root-bundle>] [**--servername**=<servername>]
[**--format**=<format>] [**--sha1**] [**--insecure**]`,
		Description: `**step certificate fingerprint** reads a certificate and prints to STDOUT the
certificate SHA256 of the raw certificate or certificate signing request.

If <crt-file> contains multiple certificates (i.e., it is a certificate
"bundle") the fingerprint of the first certificate in the bundle will be
printed. Pass the --bundle option to print all fingerprints in the order in
which they appear in the bundle.

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
e2c4f12edfc1816cc610755d32e6f45d5678ba21ecda1693bb5b246e3c48c03d
'''

Get the fingerprints for a remote certificate with its intermediate:
'''
$ step certificate fingerprint --bundle https://smallstep.com
e2c4f12edfc1816cc610755d32e6f45d5678ba21ecda1693bb5b246e3c48c03d
25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d
'''

Get the fingerprint for a CSR using base64-url encoding without padding:
'''
$ step certificate fingerprint --format base64-url-raw hello.csr
PJLNhtQoBE1yGN_ZKzr4Y2U5pyqIGiyyszkoz2raDOw
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
				Name:  `bundle`,
				Usage: `Print all fingerprints in the order in which they appear in the bundle.`,
			},
			cli.BoolFlag{
				Name: "insecure",
				Usage: `Use an insecure client to retrieve a remote peer certificate. Useful for
debugging invalid certificates remotely.`,
			},
			flags.ServerName,
			flags.FingerprintFormatFlag("hex"),
			cli.BoolFlag{
				Name:  "sha1",
				Usage: `Use the SHA-1 hash algorithm to hash the certificate. Requires **--insecure** flag.`,
			},
		},
	}
}

func fingerprintAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var (
		crtFile    = ctx.Args().Get(0)
		certs      []*x509.Certificate
		serverName = ctx.String("servername")
		roots      = ctx.String("roots")
		bundle     = ctx.Bool("bundle")
		insecure   = ctx.Bool("insecure")
		format     = ctx.String("format")
		useSHA1    = ctx.Bool("sha1")
	)

	// Use stdin if no argument is used.
	if crtFile == "" {
		crtFile = "-"
	}

	if useSHA1 && !insecure {
		return errs.RequiredInsecureFlag(ctx, "sha")
	}

	encoding, err := flags.ParseFingerprintFormat(format)
	if err != nil {
		return err
	}

	switch addr, isURL, err := trimURL(crtFile); {
	case err != nil:
		return err
	case isURL:
		certs, err = getPeerCertificates(addr, serverName, roots, insecure)
		if err != nil {
			return err
		}
	default:
		b, err := utils.ReadFile(crtFile)
		if err != nil {
			return errors.Wrapf(err, "error reading file %s", crtFile)
		}

		var pemError *pemutil.InvalidPEMError
		certs, err = pemutil.ParseCertificateBundle(b)
		switch {
		case errors.As(err, &pemError) && pemError.Type == pemutil.PEMTypeCertificate:
			csr, err := pemutil.ParseCertificateRequest(b)
			if err != nil {
				return errors.Errorf("file %s does not contain any valid CERTIFICATE or CERTIFICATE REQUEST blocks", crtFile)
			}
			certs = []*x509.Certificate{
				{Raw: csr.Raw},
			}
		case err != nil:
			return fmt.Errorf("error parsing %s: %w", crtFile, err)
		}
	}

	if !bundle {
		certs = certs[:1]
	}

	hash := crypto.SHA256
	if useSHA1 {
		hash = crypto.SHA1
	}
	for i, crt := range certs {
		fp, err := fingerprint.New(crt.Raw, hash, encoding)
		if err != nil {
			return err
		}
		if bundle {
			fmt.Printf("%d: %s\n", i, fp)
		} else {
			fmt.Println(fp)
		}
	}
	return nil
}
