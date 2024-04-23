// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crlutil

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

// OIDs for signature algorithms
var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
)

type signatureAlgorithmDetails struct {
	oid  stringer
	hash crypto.Hash
}

type stringer interface {
	String() string
}

type oidUnknown struct{}

func (o oidUnknown) String() string {
	return "unknown"
}

var signatureAlgorithmMap = map[x509.SignatureAlgorithm]signatureAlgorithmDetails{
	x509.MD2WithRSA:                {oidSignatureMD2WithRSA, crypto.Hash(0)}, // no value for MD2
	x509.MD5WithRSA:                {oidSignatureMD5WithRSA, crypto.MD5},
	x509.SHA1WithRSA:               {oidSignatureSHA1WithRSA, crypto.SHA1},
	x509.SHA256WithRSA:             {oidSignatureSHA256WithRSA, crypto.SHA256},
	x509.SHA384WithRSA:             {oidSignatureSHA384WithRSA, crypto.SHA384},
	x509.SHA512WithRSA:             {oidSignatureSHA512WithRSA, crypto.SHA512},
	x509.SHA256WithRSAPSS:          {oidSignatureRSAPSS, crypto.SHA256},
	x509.SHA384WithRSAPSS:          {oidSignatureRSAPSS, crypto.SHA384},
	x509.SHA512WithRSAPSS:          {oidSignatureRSAPSS, crypto.SHA512},
	x509.DSAWithSHA1:               {oidSignatureDSAWithSHA1, crypto.SHA1},
	x509.DSAWithSHA256:             {oidSignatureDSAWithSHA256, crypto.SHA256},
	x509.ECDSAWithSHA1:             {oidSignatureECDSAWithSHA1, crypto.SHA1},
	x509.ECDSAWithSHA256:           {oidSignatureECDSAWithSHA256, crypto.SHA256},
	x509.ECDSAWithSHA384:           {oidSignatureECDSAWithSHA384, crypto.SHA384},
	x509.ECDSAWithSHA512:           {oidSignatureECDSAWithSHA512, crypto.SHA512},
	x509.PureEd25519:               {oidSignatureEd25519, crypto.Hash(0)},
	x509.UnknownSignatureAlgorithm: {oidUnknown{}, crypto.Hash(0)},
}

type SignatureAlgorithm struct {
	Name string `json:"name"`
	OID  string `json:"oid"`
	algo x509.SignatureAlgorithm
	hash crypto.Hash
}

func (s SignatureAlgorithm) String() string {
	if s.Name == "" {
		return s.OID
	}
	return s.Name
}

func newSignatureAlgorithm(xsa x509.SignatureAlgorithm) SignatureAlgorithm {
	sa := SignatureAlgorithm{
		Name: xsa.String(),
		algo: xsa,
	}

	if sad, ok := signatureAlgorithmMap[xsa]; ok {
		sa.OID = sad.oid.String()
		sa.hash = sad.hash
	} else {
		sa.OID = "unknown"
	}

	return sa
}
