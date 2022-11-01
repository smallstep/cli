package crl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:      "inspect",
		Action:    command.ActionFunc(inspectAction),
		Usage:     "print certificate revocation list (CRL) details in human-readable format",
		UsageText: `**step crl inspect** <file|url>`,
		Description: `**step crl inspect** validates and prints the details of a certificate revocation list (CRL).
A CRL is considered valid if its signature is valid, the CA is not expired, and the next update time is in the future.

## POSITIONAL ARGUMENTS

<file|url>
:  The file or URL where the CRL is. If <--from> is passed it will inspect
the certificate and extract the CRL distribution point from.

## EXAMPLES

Inspect a CRL:
'''
$ step crl inspect --insecure http://ca.example.com/crls/exampleca.crl
'''

Inspect and validate a CRL in a file:
'''
$ step crl inspect --ca ca.crt exampleca.crl
'''

Format the CRL in JSON:
'''
$ step crl inspect --insecure --format json exampleca.crl
'''

Inspect the CRL from the CRL distribution point of a given url:
'''
$ step crl inspect --from https://www.google.com
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format",
				Value: "text",
				Usage: `The output format for printing the introspection details.

: <format> is a string and must be one of:

    **text**
    :  Print output in unstructured text suitable for a human to read.
	   This is the default format.

    **json**
    :  Print output in JSON format.

    **pem**
    :  Print output in PEM format.`,
			},
			cli.StringFlag{
				Name:  "ca",
				Usage: `The certificate <file> used to validate the CRL.`,
			},
			cli.BoolFlag{
				Name:  "from",
				Usage: `Extract CRL and CA from the URL passed as argument.`,
			},
			cli.StringSliceFlag{
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
			flags.Insecure,
		},
	}
}

func inspectAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	isFrom := ctx.Bool("from")

	// Require --insecure
	if !isFrom && ctx.String("ca") == "" && !ctx.Bool("insecure") {
		return errs.InsecureCommand(ctx)
	}

	var tlsConfig *tls.Config
	httpClient := http.Client{}
	if roots := ctx.String("roots"); roots != "" {
		pool, err := x509util.ReadCertPool(roots)
		if err != nil {
			return err
		}
		tlsConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = tlsConfig
		httpClient.Transport = tr
	}

	crlFile := ctx.Args().First()
	if crlFile == "" {
		crlFile = "-"
	}

	var isURL bool
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(crlFile), p) {
			isURL = true
			break
		}
	}

	var caCerts []*x509.Certificate
	if filename := ctx.String("ca"); filename != "" {
		var err error
		if caCerts, err = pemutil.ReadCertificateBundle(filename); err != nil {
			return err
		}
	}

	if isFrom {
		var bundle []*x509.Certificate
		if isURL {
			u, err := url.Parse(crlFile)
			if err != nil {
				return errors.Wrapf(err, "error parsing %s", crlFile)
			}
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				u.Host = net.JoinHostPort(u.Host, "443")
			}
			conn, err := tls.Dial("tcp", u.Host, tlsConfig)
			if err != nil {
				return errors.Wrapf(err, "error connecting %s", crlFile)
			}
			bundle = conn.ConnectionState().PeerCertificates
		} else {
			var err error
			if bundle, err = pemutil.ReadCertificateBundle(crlFile); err != nil {
				return err
			}
		}

		isURL = true
		if len(bundle[0].CRLDistributionPoints) == 0 {
			return errors.Errorf("failed to get CRL distribution points from %s", crlFile)
		}

		crlFile = bundle[0].CRLDistributionPoints[0]
		if len(bundle) > 1 {
			caCerts = append(caCerts, bundle[1:]...)
		}

		if len(caCerts) == 0 && !ctx.Bool("insecure") {
			return errs.InsecureCommand(ctx)
		}
	}

	var (
		b   []byte
		err error
	)
	if isURL {
		resp, err := httpClient.Get(crlFile)
		if err != nil {
			return errors.Wrap(err, "error downloading crl")
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return errors.Errorf("error downloading crl: status code %d", resp.StatusCode)
		}
		b, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "error downloading crl")
		}
	} else {
		b, err = utils.ReadFile(crlFile)
		if err != nil {
			return err
		}
	}

	crl, err := ParseCRL(b)
	if err != nil {
		return errors.Wrap(err, "error parsing crl")
	}

	if len(caCerts) > 0 {
		for _, crt := range caCerts {
			if (crt.KeyUsage&x509.KeyUsageCRLSign) == 0 || len(crt.SubjectKeyId) == 0 {
				continue
			}
			if crl.authorityKeyID == nil || bytes.Equal(crt.SubjectKeyId, crl.authorityKeyID) {
				if crl.Verify(crt) {
					crl.Signature.Valid = true
				}
			}
		}
	}

	switch ctx.String("format") {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(crl); err != nil {
			return errors.Wrap(err, "error marshaling crl")
		}
	case "pem":
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "X509 CRL",
			Bytes: b,
		})
	default:
		printCRL(crl)
	}

	return nil
}

// CRL is the JSON representation of a certificate revocation list.
type CRL struct {
	Version             int                  `json:"version"`
	SignatureAlgorithm  SignatureAlgorithm   `json:"signature_algorithm"`
	Issuer              DistinguishedName    `json:"issuer"`
	ThisUpdate          time.Time            `json:"this_update"`
	NextUpdate          time.Time            `json:"next_update"`
	RevokedCertificates []RevokedCertificate `json:"revoked_certificates"`
	Extensions          []Extension          `json:"extensions,omitempty"`
	Signature           *Signature           `json:"signature"`
	authorityKeyID      []byte
	raw                 []byte
}

func ParseCRL(b []byte) (*CRL, error) {
	crl, err := x509.ParseCRL(b)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing crl")
	}
	tcrl := crl.TBSCertList

	certs := make([]RevokedCertificate, len(tcrl.RevokedCertificates))
	for i, c := range tcrl.RevokedCertificates {
		certs[i] = newRevokedCertificate(c)
	}

	var issuerKeyID []byte
	extensions := make([]Extension, len(tcrl.Extensions))
	for i, e := range tcrl.Extensions {
		extensions[i] = newExtension(e)
		if e.Id.Equal(oidExtensionAuthorityKeyID) {
			var v authorityKeyID
			if _, err := asn1.Unmarshal(e.Value, &v); err == nil {
				issuerKeyID = v.ID
			}
		}
	}

	return &CRL{
		Version:             tcrl.Version + 1,
		SignatureAlgorithm:  newSignatureAlgorithm(tcrl.Signature),
		Issuer:              newDistinguishedName(tcrl.Issuer),
		ThisUpdate:          tcrl.ThisUpdate,
		NextUpdate:          tcrl.NextUpdate,
		RevokedCertificates: certs,
		Extensions:          extensions,
		Signature: &Signature{
			SignatureAlgorithm: newSignatureAlgorithm(tcrl.Signature),
			Value:              crl.SignatureValue.Bytes,
			Valid:              false,
			Reason:             "",
		},
		authorityKeyID: issuerKeyID,
		raw:            crl.TBSCertList.Raw,
	}, nil
}

func (c *CRL) Verify(ca *x509.Certificate) bool {
	now := time.Now()
	if now.After(c.NextUpdate) {
		c.Signature.Reason = "CRL has expired"
		return false
	}
	if now.After(ca.NotAfter) {
		c.Signature.Reason = "CA certificate has expired"
		return false
	}

	if !c.VerifySignature(ca) {
		c.Signature.Reason = "Signature does not match"
		return false
	}

	return true
}

func (c *CRL) VerifySignature(ca *x509.Certificate) bool {
	var sum []byte
	var hash crypto.Hash
	if hash = c.SignatureAlgorithm.hash; hash > 0 {
		h := hash.New()
		h.Write(c.raw)
		sum = h.Sum(nil)
	}

	sig := c.Signature.Value
	switch pub := ca.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, sum, sig)
	case *rsa.PublicKey:
		switch c.SignatureAlgorithm.algo {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return rsa.VerifyPSS(pub, hash, sum, sig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
			}) == nil
		default:
			return rsa.VerifyPKCS1v15(pub, hash, sum, sig) == nil
		}
	case ed25519.PublicKey:
		return ed25519.Verify(pub, c.raw, sig)
	default:
		return false
	}
}

func printCRL(crl *CRL) {
	fmt.Println("Certificate Revocation List (CRL):")
	fmt.Println("    Data:")
	fmt.Printf("        Valid: %v\n", crl.Signature.Valid)
	if len(crl.Signature.Reason) > 0 {
		fmt.Printf("        Reason: %s\n", crl.Signature.Reason)
	}
	fmt.Printf("        Version: %d (0x%x)\n", crl.Version, crl.Version-1)
	fmt.Println("    Signature algorithm:", crl.SignatureAlgorithm)
	fmt.Println("        Issuer:", crl.Issuer)
	fmt.Println("        Last Update:", crl.ThisUpdate.UTC())
	fmt.Println("        Next Update:", crl.NextUpdate.UTC())
	fmt.Println("        CRL Extensions:")
	for _, e := range crl.Extensions {
		fmt.Println(spacer(12) + e.Name)
		for _, s := range e.Details {
			fmt.Println(spacer(16) + s)
		}
	}
	if len(crl.RevokedCertificates) == 0 {
		fmt.Println(spacer(8) + "No Revoked Certificates.")
	} else {
		fmt.Println(spacer(8) + "Revoked Certificates:")
		for _, crt := range crl.RevokedCertificates {
			fmt.Printf(spacer(12)+"Serial Number: %s (0x%X)\n", crt.SerialNumber, crt.SerialNumberBytes)
			fmt.Println(spacer(16)+"Revocation Date:", crt.RevocationTime.UTC())
			if len(crt.Extensions) > 0 {
				fmt.Println(spacer(16) + "CRL Entry Extensions:")
				for _, e := range crt.Extensions {
					fmt.Println(spacer(20) + e.Name)
					for _, s := range e.Details {
						fmt.Println(spacer(24) + s)
					}
				}
			}
		}
	}

	fmt.Println("    Signature Algorithm:", crl.Signature.SignatureAlgorithm)
	printBytes(crl.Signature.Value, spacer(8))
}

// Signature is the JSON representation of a CRL signature.
type Signature struct {
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Value              []byte             `json:"value"`
	Valid              bool               `json:"valid"`
	Reason             string             `json:"reason,omitempty"`
}

// DistinguishedName is the JSON representation of the CRL issuer.
type DistinguishedName struct {
	Country            []string                 `json:"country,omitempty"`
	Organization       []string                 `json:"organization,omitempty"`
	OrganizationalUnit []string                 `json:"organizational_unit,omitempty"`
	Locality           []string                 `json:"locality,omitempty"`
	Province           []string                 `json:"province,omitempty"`
	StreetAddress      []string                 `json:"street_address,omitempty"`
	PostalCode         []string                 `json:"postal_code,omitempty"`
	SerialNumber       string                   `json:"serial_number,omitempty"`
	CommonName         string                   `json:"common_name,omitempty"`
	ExtraNames         map[string][]interface{} `json:"extra_names,omitempty"`
	raw                pkix.RDNSequence
}

// String returns the one line representation of the distinguished name.
func (d DistinguishedName) String() string {
	var parts []string
	for _, dn := range d.raw {
		v := strings.ReplaceAll(pkix.RDNSequence{dn}.String(), "\\,", ",")
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}

func newDistinguishedName(seq pkix.RDNSequence) DistinguishedName {
	var n pkix.Name
	n.FillFromRDNSequence(&seq)

	var extraNames map[string][]interface{}
	if len(n.ExtraNames) > 0 {
		extraNames = make(map[string][]interface{})
		for _, tv := range n.ExtraNames {
			oid := tv.Type.String()
			if s, ok := tv.Value.(string); ok {
				extraNames[oid] = append(extraNames[oid], s)
				continue
			}
			if b, err := asn1.Marshal(tv.Value); err == nil {
				extraNames[oid] = append(extraNames[oid], b)
				continue
			}
			extraNames[oid] = append(extraNames[oid], escapeValue(tv.Value))
		}
	}

	return DistinguishedName{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
		ExtraNames:         extraNames,
		raw:                seq,
	}
}

// RevokedCertificate is the JSON representation of a certificate in a CRL.
type RevokedCertificate struct {
	SerialNumber      string      `json:"serial_number"`
	RevocationTime    time.Time   `json:"revocation_time"`
	Extensions        []Extension `json:"extensions,omitempty"`
	SerialNumberBytes []byte      `json:"-"`
}

func newRevokedCertificate(c pkix.RevokedCertificate) RevokedCertificate {
	var extensions []Extension

	return RevokedCertificate{
		SerialNumber:      c.SerialNumber.String(),
		RevocationTime:    c.RevocationTime.UTC(),
		Extensions:        extensions,
		SerialNumberBytes: c.SerialNumber.Bytes(),
	}
}

func spacer(i int) string {
	return fmt.Sprintf("%"+strconv.Itoa(i)+"s", "")
}

func printBytes(bs []byte, prefix string) {
	for i, b := range bs {
		if i == 0 {
			fmt.Print(prefix)
		} else if (i % 16) == 0 {
			fmt.Print("\n" + prefix)
		}
		fmt.Printf("%02x", b)
		if i != len(bs)-1 {
			fmt.Print(":")
		}
	}
	fmt.Println()
}

func escapeValue(v interface{}) string {
	s := fmt.Sprint(v)
	escaped := make([]rune, 0, len(s))

	for k, c := range s {
		escape := false

		switch c {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true

		case ' ':
			escape = k == 0 || k == len(s)-1

		case '#':
			escape = k == 0
		}

		if escape {
			escaped = append(escaped, '\\', c)
		} else {
			escaped = append(escaped, c)
		}
	}

	return string(escaped)
}
