package crlutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

// CRL is the JSON representation of a certificate revocation list.
type CRL struct {
	Version             *big.Int             `json:"version"`
	SignatureAlgorithm  SignatureAlgorithm   `json:"signature_algorithm"`
	Issuer              DistinguishedName    `json:"issuer"`
	ThisUpdate          time.Time            `json:"this_update"`
	NextUpdate          time.Time            `json:"next_update"`
	RevokedCertificates []RevokedCertificate `json:"revoked_certificates"`
	Extensions          []Extension          `json:"extensions,omitempty"`
	Signature           *Signature           `json:"signature"`
	AuthorityKeyID      []byte
	Raw                 []byte
}

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// pemType is the type of a PEM encoded CRL.
var pemType = "X509 CRL"

func ParseCRL(b []byte) (*CRL, error) {
	if bytes.HasPrefix(b, pemCRLPrefix) {
		block, _ := pem.Decode(b)
		if block != nil && block.Type == pemType {
			b = block.Bytes
		}
	}

	crl, err := x509.ParseRevocationList(b)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing crl")
	}

	certs := make([]RevokedCertificate, len(crl.RevokedCertificateEntries))
	for i, c := range crl.RevokedCertificateEntries {
		certs[i] = newRevokedCertificate(c)
	}

	var issuerKeyID []byte
	extensions := make([]Extension, len(crl.Extensions))
	for i, e := range crl.Extensions {
		extensions[i] = newExtension(e)
		if e.Id.Equal(oidExtensionAuthorityKeyID) {
			var v authorityKeyID
			if _, err := asn1.Unmarshal(e.Value, &v); err == nil {
				issuerKeyID = v.ID
			}
		}
	}

	sa := newSignatureAlgorithm(crl.SignatureAlgorithm)

	return &CRL{
		Version:             crl.Number.Add(crl.Number, big.NewInt(1)),
		SignatureAlgorithm:  sa,
		Issuer:              newDistinguishedName(crl.Issuer),
		ThisUpdate:          crl.ThisUpdate,
		NextUpdate:          crl.NextUpdate,
		RevokedCertificates: certs,
		Extensions:          extensions,
		Signature: &Signature{
			SignatureAlgorithm: sa,
			Value:              crl.Signature,
			Valid:              false,
			Reason:             "",
		},
		AuthorityKeyID: issuerKeyID,
		Raw:            crl.RawTBSRevocationList,
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
		h.Write(c.Raw)
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
		return ed25519.Verify(pub, c.Raw, sig)
	default:
		return false
	}
}

func PrintCRL(crl *CRL) {
	fmt.Println("Certificate Revocation List (CRL):")
	fmt.Println("    Data:")
	fmt.Printf("        Valid: %v\n", crl.Signature.Valid)
	if crl.Signature.Reason != "" {
		fmt.Printf("        Reason: %s\n", crl.Signature.Reason)
	}
	fmt.Printf("        Version: %d (0x%x)\n", crl.Version, crl.Version.Add(crl.Version, big.NewInt(-1)))
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
	dn                 pkix.Name
}

// String returns the one line representation of the distinguished name.
func (d DistinguishedName) String() string {
	return d.dn.String()
}

func newDistinguishedName(dn pkix.Name) DistinguishedName {
	var extraNames map[string][]interface{}
	if len(dn.ExtraNames) > 0 {
		extraNames = make(map[string][]interface{})
		for _, tv := range dn.ExtraNames {
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
		Country:            dn.Country,
		Organization:       dn.Organization,
		OrganizationalUnit: dn.OrganizationalUnit,
		Locality:           dn.Locality,
		Province:           dn.Province,
		StreetAddress:      dn.StreetAddress,
		PostalCode:         dn.PostalCode,
		SerialNumber:       dn.SerialNumber,
		CommonName:         dn.CommonName,
		ExtraNames:         extraNames,
	}
}

// RevokedCertificate is the JSON representation of a certificate in a CRL.
type RevokedCertificate struct {
	SerialNumber      string      `json:"serial_number"`
	RevocationTime    time.Time   `json:"revocation_time"`
	Extensions        []Extension `json:"extensions,omitempty"`
	SerialNumberBytes []byte      `json:"-"`
}

func newRevokedCertificate(c x509.RevocationListEntry) RevokedCertificate {
	extensions := make([]Extension, len(c.Extensions))

	for i, e := range c.Extensions {
		extensions[i] = newExtension(e)
	}

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
