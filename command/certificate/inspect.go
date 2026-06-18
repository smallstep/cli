package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certinfo"
	"github.com/smallstep/cli-utils/errs"
	zx509 "github.com/smallstep/zcrypto/x509"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:   "inspect",
		Action: cli.ActionFunc(inspectAction),
		Usage:  `print certificate or CSR details in human readable format`,
		UsageText: `**step certificate inspect** <crt-file>
[**--bundle**] [**--short**] [**--format**=<format>] [**--roots**=<root-bundle>]
[**--servername**=<servername>]`,
		Description: `**step certificate inspect** prints the details of the
certificate or CSR in a human- or machine-readable format. Beware: Local certificates
are never verified. Always verify a certificate (using **step certificate verify**)
before relying on the output of this command.

If crt-file contains multiple certificates (i.e., it is a certificate "bundle")
the first certificate in the bundle will be output. Pass the --bundle option to
print all certificates in the order in which they appear in the bundle.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate or certificate signing request (CSR) to inspect. A hyphen ("-") indicates STDIN as <crt-file>.

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

Inspect a remote certificate (using the standard port derived from the URL prefix):
'''
$ step certificate inspect smtps://smtp.gmail.com
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

Inspect a remote certificate chain in PEM format:
'''
$ step certificate inspect https://smallstep.com --format pem --bundle
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
    :  Print output in JSON format.

    **pem**
    :  Print output in PEM format.`,
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
			cli.BoolFlag{
				Name: `bundle`,
				Usage: `Print all certificates in the order in which they appear in the bundle.
If the output format is 'json' then output a list of certificates, even if
the bundle only contains one certificate. This flag will result in an error
if the input bundle includes any PEM that does not have type CERTIFICATE.`,
			},
			cli.BoolFlag{
				Name:  "short",
				Usage: "Print the certificate or CSR details in shorter and more friendly format.",
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
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var (
		crtFile    = ctx.Args().Get(0)
		bundle     = ctx.Bool("bundle")
		format     = ctx.String("format")
		roots      = ctx.String("roots")
		serverName = ctx.String("servername")
		short      = ctx.Bool("short")
		insecure   = ctx.Bool("insecure")
	)

	// Use stdin if no argument is used.
	if crtFile == "" {
		crtFile = "-"
	}

	if format != "text" && format != "json" && format != "pem" {
		return errs.InvalidFlagValue(ctx, "format", format, "text, json, pem")
	}
	if short && (format == "json" || format == "pem") {
		return errs.IncompatibleFlagWithFlag(ctx, "short", "format "+format)
	}

	switch addr, isURL, err := trimURL(crtFile); {
	case err != nil:
		return err
	case isURL:
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, insecure)
		if err != nil {
			return err
		}
		if bundle {
			return inspectCertificates(ctx, peerCertificates, os.Stdout)
		}
		return inspectCertificates(ctx, peerCertificates[:1], os.Stdout)
	default: // is not URL
		b, err := utils.ReadFile(crtFile)
		if err != nil {
			return errors.Wrapf(err, "error reading file %s", crtFile)
		}

		var pemError *pemutil.InvalidPEMError
		crts, err := pemutil.ParseCertificateBundle(b)
		switch {
		case errors.As(err, &pemError) && pemError.Type == pemutil.PEMTypeCertificate:
			csr, err := pemutil.ParseCertificateRequest(b)
			if err != nil {
				return errors.Errorf("file %s does not contain any valid CERTIFICATE or CERTIFICATE REQUEST blocks", crtFile)
			}
			return inspectCertificateRequest(ctx, csr, os.Stdout)
		case err != nil:
			return fmt.Errorf("error parsing %s: %w", crtFile, err)
		default:
			if bundle {
				return inspectCertificates(ctx, crts, os.Stdout)
			}
			return inspectCertificates(ctx, crts[:1], os.Stdout)
		}
	}
}

func inspectCertificates(ctx *cli.Context, crts []*x509.Certificate, w io.Writer) error {
	var err error
	format, short := ctx.String("format"), ctx.Bool("short")
	switch format {
	case "text":
		var text string
		for _, crt := range crts {
			if short {
				if text, err = certinfo.CertificateShortText(crt); err != nil {
					return err
				}
			} else {
				if text, err = certinfo.CertificateText(crt); err != nil {
					return err
				}
			}
			fmt.Fprint(w, text)
			printLogotypes(crt, w)
		}
		return nil
	case "json":
		var v interface{}
		if len(crts) == 1 {
			zcrt, err := zx509.ParseCertificate(crts[0].Raw)
			if err != nil {
				return errors.WithStack(err)
			}
			v = struct{ *zx509.Certificate }{zcrt}
		} else {
			var zcrts []*zx509.Certificate
			for _, crt := range crts {
				zcrt, err := zx509.ParseCertificate(crt.Raw)
				if err != nil {
					return errors.WithStack(err)
				}
				zcrts = append(zcrts, zcrt)
			}
			v = zcrts
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err := enc.Encode(v)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "pem":
		for _, crt := range crts {
			err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
			if err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	default:
		return errs.InvalidFlagValue(ctx, "format", format, "text, json, pem")
	}
}

func inspectCertificateRequest(ctx *cli.Context, csr *x509.CertificateRequest, w io.Writer) error {
	var err error
	format, short := ctx.String("format"), ctx.Bool("short")
	switch format {
	case "text":
		var text string
		if short {
			text, err = certinfo.CertificateRequestShortText(csr)
			if err != nil {
				return err
			}
		} else {
			text, err = certinfo.CertificateRequestText(csr)
			if err != nil {
				return err
			}
		}
		fmt.Fprint(w, text)
		return nil
	case "json":
		zcsr, err := zx509.ParseCertificateRequest(csr.Raw)
		if err != nil {
			return errors.WithStack(err)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(zcsr); err != nil {
			return errors.WithStack(err)
		}
		return nil
	case "pem":
		err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	default:
		return errs.InvalidFlagValue(ctx, "format", format, "text, json")
	}
}

type HashAlgAndValue struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashValue     []byte
}

type LogotypeDetails struct {
	MediaType    string `asn1:"ia5"`
	LogotypeHash []HashAlgAndValue
	LogotypeURI  []string
}

type LogotypeImageInfo struct {
	Type       int `asn1:"optional,tag:0"`
	FileSize   int
	XSize      int
	YSize      int
	Resolution asn1.RawValue `asn1:"optional"`
	Language   string        `asn1:"optional,ia5,tag:4"`
}

type LogotypeImage struct {
	ImageDetails LogotypeDetails
	ImageInfo    LogotypeImageInfo `asn1:"optional"`
}

type LogotypeAudioInfo struct {
	FileSize   int
	PlayTime   int
	Channels   int
	SampleRate int    `asn1:"optional,tag:3"`
	Language   string `asn1:"optional,ia5,tag:4"`
}

type LogotypeAudio struct {
	AudioDetails LogotypeDetails
	AudioInfo    LogotypeAudioInfo `asn1:"optional"`
}

type LogotypeData struct {
	Image []LogotypeImage `asn1:"optional"`
	Audio []LogotypeAudio `asn1:"optional,tag:1"`
}

type LogotypeReference struct {
	RefStructHash []HashAlgAndValue
	RefStructURI  []string
}

type OtherLogotypeInfo struct {
	LogotypeType asn1.ObjectIdentifier
	Info         asn1.RawValue
}

type LogotypeExtn struct {
	CommunityLogos []asn1.RawValue `asn1:"explicit,optional,tag:0"`
	IssuerLogo     asn1.RawValue   `asn1:"explicit,optional,tag:1"`
	SubjectLogo    asn1.RawValue   `asn1:"explicit,optional,tag:2"`
	OtherLogos     []asn1.RawValue `asn1:"explicit,optional,tag:3"`
}

func unmarshalImplicitSequence(val asn1.RawValue, out interface{}) error {
	der := val.FullBytes
	if len(der) == 0 {
		return io.EOF
	}
	derCopy := make([]byte, len(der))
	copy(derCopy, der)
	derCopy[0] = 0x30
	_, err := asn1.Unmarshal(derCopy, out)
	return err
}

func parseLogotypeURIs(value []byte) ([]string, error) {
	var ext LogotypeExtn
	if _, err := asn1.Unmarshal(value, &ext); err != nil {
		return nil, err
	}

	var uris []string

	extractFromInfo := func(raw asn1.RawValue) {
		switch raw.Tag {
		case 0: // direct (LogotypeData)
			var data LogotypeData
			if err := unmarshalImplicitSequence(raw, &data); err == nil {
				for _, img := range data.Image {
					uris = append(uris, img.ImageDetails.LogotypeURI...)
				}
				for _, aud := range data.Audio {
					uris = append(uris, aud.AudioDetails.LogotypeURI...)
				}
			}
		case 1: // indirect (LogotypeReference)
			var ref LogotypeReference
			if err := unmarshalImplicitSequence(raw, &ref); err == nil {
				uris = append(uris, ref.RefStructURI...)
			}
		}
	}

	// 1. communityLogos
	for _, logoInfo := range ext.CommunityLogos {
		extractFromInfo(logoInfo)
	}

	// 2. issuerLogo
	if len(ext.IssuerLogo.Bytes) > 0 {
		var choice asn1.RawValue
		if _, err := asn1.Unmarshal(ext.IssuerLogo.Bytes, &choice); err == nil {
			extractFromInfo(choice)
		}
	}

	// 3. subjectLogo
	if len(ext.SubjectLogo.Bytes) > 0 {
		var choice asn1.RawValue
		if _, err := asn1.Unmarshal(ext.SubjectLogo.Bytes, &choice); err == nil {
			extractFromInfo(choice)
		}
	}

	// 4. otherLogos
	for _, other := range ext.OtherLogos {
		var otherInfo OtherLogotypeInfo
		if _, err := asn1.Unmarshal(other.FullBytes, &otherInfo); err == nil {
			extractFromInfo(otherInfo.Info)
		}
	}

	return uris, nil
}

func printLogotypes(crt *x509.Certificate, w io.Writer) {
	for _, ext := range crt.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}) {
			uris, err := parseLogotypeURIs(ext.Value)
			if err == nil && len(uris) > 0 {
				for _, uri := range uris {
					fmt.Fprintf(w, "Logotype URI: %s\n", uri)
				}
			}
		}
	}
}
