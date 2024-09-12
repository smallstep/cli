package winpe

import (
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"io"
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.mozilla.org/pkcs7"

	"github.com/smallstep/cli-utils/errs"
)

// Command returns the winpe subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "winpe",
		Usage:     "extract certificates and verify Windows Portable Executable files",
		UsageText: "step crypto winpe <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto winpe** command group provides facilities to extract certificates and
verify Windows Portable Executable files.

## EXAMPLES

Extract all certificates and output in JSON format:
'''
step crypto winpe extract my.exe | step certificate inspect --format json --bundle
'''`,
		Subcommands: cli.Commands{
			extractCommand(),
		},
	}
}

// ErrCodeSignCertsNoCertificateTableFound is the error indicating that no
// certificate table was found.
var ErrCodeSignCertsNoCertificateTableFound = errors.New("No Certificate Table found")

func extractCommand() cli.Command {
	return cli.Command{
		Name:      "extract",
		Action:    cli.ActionFunc(extractPEAction),
		Usage:     "extract certificates from Windows Portable Executable files",
		UsageText: `**step crypto winpe extract** <file>`,
		Description: `**step crypto winpe extract** extract certificate from a Windows Portable Executable file in PEM format.

For examples, see **step help crypto winpe**.

## POSITIONAL ARGUMENTS

<file>
: The path to a Windows Portable Executable file`,
	}
}

func extractPEAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	return extractPE(path.Clean(ctx.Args().Get(0)))
}

func extractPE(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return errors.Wrapf(err, "error opening %s", filename)
	}
	defer file.Close()

	f, err := pe.NewFile(file)
	if err != nil {
		return errors.Wrap(err, "Unable to open the PE file")
	}
	defer f.Close()

	var (
		buff []byte
		ob   *asn1.ObjectIdentifier
	)

	switch header := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		buff, ob, err = codeSignCertsParseHeader32(header, file)
	case *pe.OptionalHeader64:
		buff, ob, err = codeSignCertsParseHeader64(header, file)
	default:
		err = errors.Errorf("Header of type %T is not supported", header)
	}

	if err != nil {
		return errors.Wrap(err, "Error parsing the executable's headers")
	}

	err = codeSignCertsParseCertificateTable(buff, ob, os.Stdout)
	if err != nil {
		return errors.Wrap(err, "Error to parse the certificate table from the executable's table")
	}

	return nil
}

// Wrapper Functions
// PE headers can be written by 64 bits architectures or 32 bits architectures.
// 32 bits is IMHO more spread out because it's backward compatible with 64 bits.
// I don't think it changes the fact that the program can for a 64 bits arch and the headers 32 bits.
func codeSignCertsParseHeader64(header *pe.OptionalHeader64, file io.ReaderAt) ([]byte, *asn1.ObjectIdentifier, error) {
	return codeSignCertsExtractCerts(header.DataDirectory[4], file)
}
func codeSignCertsParseHeader32(header *pe.OptionalHeader32, file io.ReaderAt) ([]byte, *asn1.ObjectIdentifier, error) {
	return codeSignCertsExtractCerts(header.DataDirectory[4], file)
}

func codeSignCertsExtractCerts(header pe.DataDirectory, file io.ReaderAt) ([]byte, *asn1.ObjectIdentifier, error) {
	// The certificate table is the 5th header: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#file-headers
	if header.VirtualAddress == 0 {
		return nil, nil, ErrCodeSignCertsNoCertificateTableFound
	}

	// The payload starts 8 bytes after the header's virtual address value
	// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#file-headers
	// 4 bytes: Specifies the length of the attribute certificate entry.
	// 2 bytes: Contains the certificate version number.
	// 2 bytes: Specifies the type of content in bCertificate.
	start := header.VirtualAddress + 8
	stop := start + (header.Size - 8) // the attribute Size is the same as what's in the 4 bytes at VirtualAddress, removing 8 bytes since they are added to the VirtualAddressValue
	size := stop - start

	certType, err := ExtractReadAt(file, 2, int64(header.VirtualAddress+6))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error to extract wCertificateType")
	}

	// 0x0002 WIN_CERT_TYPE_PKCS_SIGNED_DATA Certificate contains a PKCS#7 SignedData structure
	if t := binary.LittleEndian.Uint16(certType); t != 2 {
		return nil, nil, errors.Wrapf(err, "wCertificateType of %d is not supported", t)
	}

	buff, err := ExtractReadAt(file, int(size), int64(start))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error reading certificate table first entry")
	}

	ct := &codeSignCertsCertificateTable{}
	_, err = asn1.Unmarshal(buff, ct)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error unmarshaling certificate table from ASN.1")
	}

	return buff, &ct.Identifier, nil
}

type codeSignCertsCertificateTable struct {
	Identifier      asn1.ObjectIdentifier
	RawCertificates asn1.RawValue
}

// ExtractReadAt reads from the buffer starting at a given offset.
func ExtractReadAt(reader io.ReaderAt, l int, off int64) ([]byte, error) {
	buff := make([]byte, l)

	read, err := reader.ReadAt(buff, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if read != len(buff) {
		return nil, io.ErrShortWrite
	}

	return buff, nil
}

func codeSignCertsParseCertificateTable(buff []byte, ob *asn1.ObjectIdentifier, writer io.Writer) error {
	// The signed data is OID 1.2.840.113549.1.7.2
	// - https://www.alvestrand.no/objectid/1.2.840.113549.1.7.2.html
	// - 0x0002 WIN_CERT_TYPE_PKCS_SIGNED_DATA Certificate contains a PKCS#7 SignedData structure
	if ob.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		p7, err := pkcs7.Parse(buff)
		if err != nil {
			return errors.Wrap(err, "Error parsing Certificate Table entry to PKCS7")
		}

		for _, cert := range p7.Certificates {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}

			err := pem.Encode(writer, block)
			if err != nil {
				return errors.Wrap(err, "Error encoding certificate to PEM")
			}
		}

		return nil
	}

	return errors.Errorf("Certificate Table's entry type of %s is not supported\n", ob.String())
}
