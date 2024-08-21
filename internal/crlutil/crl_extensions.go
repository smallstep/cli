package crlutil

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
)

var (
	oidExtensionReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidExtensionCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtensionAuthorityKeyID           = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

func parseReasonCode(b []byte) string {
	var reasonCode asn1.Enumerated
	if _, err := asn1.Unmarshal(b, &reasonCode); err != nil {
		return sanitizeBytes(b)
	}
	switch reasonCode {
	case 0:
		return "Unspecified"
	case 1:
		return "Key Compromise"
	case 2:
		return "CA Compromise"
	case 3:
		return "Affiliation Changed"
	case 4:
		return "Superseded"
	case 5:
		return "Cessation Of Operation"
	case 6:
		return "Certificate Hold"
	case 8:
		return "Remove From CRL"
	case 9:
		return "Privilege Withdrawn"
	case 10:
		return "AA Compromise"
	default:
		return fmt.Sprintf("ReasonCode(%d): unknown", reasonCode)
	}
}

// RFC 5280,  4.2.1.1
type authorityKeyID struct {
	ID []byte `asn1:"optional,tag:0"`
}

// RFC 5280, 5.2.5
type distributionPoint struct {
	DistributionPoint          distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString        `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func (d distributionPoint) FullNames() []string {
	var names []string
	for _, v := range d.DistributionPoint.FullName {
		switch v.Class {
		case 2:
			names = append(names, fmt.Sprintf("URI:%s", v.Bytes))
		default:
			names = append(names, fmt.Sprintf("Class(%d):%s", v.Class, v.Bytes))
		}
	}
	return names
}

type Extension struct {
	Name    string   `json:"-"`
	Details []string `json:"-"`
	json    map[string]any
}

func (e *Extension) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.json)
}

func (e *Extension) AddDetailf(format string, args ...any) {
	e.Details = append(e.Details, fmt.Sprintf(format, args...))
}

func (e *Extension) AddDetail(detail string) {
	e.Details = append(e.Details, detail)
}

func newExtension(e pkix.Extension) Extension {
	var ext Extension
	switch {
	case e.Id.Equal(oidExtensionReasonCode):
		ext.Name = "X509v3 CRL Reason Code:"
		value := parseReasonCode(e.Value)
		ext.AddDetail(value)
		ext.json = map[string]any{
			"crl_reason_code": value,
		}

	case e.Id.Equal(oidExtensionCRLNumber):
		ext.Name = "X509v3 CRL Number:"
		var n *big.Int
		if _, err := asn1.Unmarshal(e.Value, &n); err == nil {
			ext.AddDetail(n.String())
			ext.json = map[string]any{
				"crl_number": n.String(),
			}
		} else {
			ext.AddDetail(sanitizeBytes(e.Value))
			ext.json = map[string]any{
				"crl_number": e.Value,
			}
		}

	case e.Id.Equal(oidExtensionAuthorityKeyID):
		var v authorityKeyID
		ext.Name = "X509v3 Authority Key Identifier:"
		ext.json = map[string]any{
			"authority_key_id": hex.EncodeToString(e.Value),
		}
		if _, err := asn1.Unmarshal(e.Value, &v); err == nil {
			var s string
			for _, b := range v.ID {
				s += fmt.Sprintf(":%02X", b)
			}
			ext.AddDetail("keyid" + s)
		} else {
			ext.AddDetail(sanitizeBytes(e.Value))
		}
	case e.Id.Equal(oidExtensionIssuingDistributionPoint):
		ext.Name = "X509v3 Issuing Distribution Point:"

		var v distributionPoint
		if _, err := asn1.Unmarshal(e.Value, &v); err != nil {
			ext.AddDetail(sanitizeBytes(e.Value))
			ext.json = map[string]any{
				"issuing_distribution_point": e.Value,
			}
		} else {
			names := v.FullNames()
			if len(names) > 0 {
				ext.AddDetail("Full Name:")
				for _, n := range names {
					ext.AddDetail("    " + n)
				}
			}
			js := map[string]any{
				"full_names": names,
			}

			// Only one of this should be set to true. But for inspect we
			// will allow more than one.
			if v.OnlyContainsUserCerts {
				ext.AddDetail("Only User Certificates")
				js["only_user_certificates"] = true
			}
			if v.OnlyContainsCACerts {
				ext.AddDetail("Only CA Certificates")
				js["only_ca_certificates"] = true
			}
			if v.OnlyContainsAttributeCerts {
				ext.AddDetail("Only Attribute Certificates")
				js["only_attribute_certificates"] = true
			}
			if len(v.OnlySomeReasons.Bytes) > 0 {
				ext.AddDetailf("Reasons: %x", v.OnlySomeReasons.Bytes)
				js["only_some_reasons"] = v.OnlySomeReasons.Bytes
			}

			ext.json = map[string]any{
				"issuing_distribution_point": js,
			}
		}
	default:
		ext.Name = e.Id.String()
		ext.AddDetail(sanitizeBytes(e.Value))
		ext.json = map[string]any{
			ext.Name: e.Value,
		}
	}

	if e.Critical {
		ext.Name += " critical"
		ext.json["critical"] = true
	}

	return ext
}

func sanitizeBytes(b []byte) string {
	value := bytes.Runes(b)
	sanitized := make([]rune, len(value))
	for i, r := range value {
		if strconv.IsPrint(r) && r != '�' {
			sanitized[i] = r
		} else {
			sanitized[i] = '.'
		}
	}
	return string(sanitized)
}
