package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:        "inspect",
		Action:      command.ActionFunc(inspectAction),
		Usage:       "print certificate revocation list or CRL details in human readable format",
		UsageText:   `**step crl inspect** <file|url>`,
		Description: `**step crl inspect** prints the details of a certificate revocation list (CRL).`,
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
		},
	}
}

func inspectAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
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

	var (
		b   []byte
		err error
	)
	if isURL {
		resp, err := http.Get(crlFile)
		if err != nil {
			return errors.Wrap(err, "error downloading crl")
		}
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

type CRL struct {
	Version             int                  `json:"version"`
	SignatureAlgorithm  SignatureAlgorithm   `json:"signature_algorithm"`
	Issuer              DistinguisedName     `json:"issuer"`
	ThisUpdate          time.Time            `json:"this_update"`
	NextUpdate          time.Time            `json:"next_update"`
	RevokedCertificates []RevokedCertificate `json:"revoked_certificates"`
	Extensions          []Extension          `json:"extensions,omitempty"`
	Signature           *Signature           `json:"signature"`
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

	extensions := make([]Extension, len(tcrl.Extensions))
	for i, e := range tcrl.Extensions {
		extensions[i] = nexExtension(e)
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
		},
	}, nil
}

func printCRL(crl *CRL) {
	fmt.Println("Certificate Revocation List (CRL):")
	fmt.Println("    Data:")
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
	fmt.Println("    Signature:")
	printBytes(crl.Signature.Value, spacer(8))
}

type Signature struct {
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	Value              []byte             `json:"value"`
	Valid              bool               `json:"valid"`
}

type DistinguisedName struct {
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

func (d DistinguisedName) String() string {
	var parts []string
	for _, dn := range d.raw {
		v := strings.ReplaceAll(pkix.RDNSequence{dn}.String(), "\\,", ",")
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}

func newDistinguishedName(seq pkix.RDNSequence) DistinguisedName {
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

	return DistinguisedName{
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
