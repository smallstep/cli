// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crl

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
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

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var signatureAlgorithmDetails = []struct {
	algo x509.SignatureAlgorithm
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{x509.MD2WithRSA, oidSignatureMD2WithRSA, crypto.Hash(0)}, // no value for MD2
	{x509.MD5WithRSA, oidSignatureMD5WithRSA, crypto.MD5},
	{x509.SHA1WithRSA, oidSignatureSHA1WithRSA, crypto.SHA1},
	{x509.SHA1WithRSA, oidISOSignatureSHA1WithRSA, crypto.SHA1},
	{x509.SHA256WithRSA, oidSignatureSHA256WithRSA, crypto.SHA256},
	{x509.SHA384WithRSA, oidSignatureSHA384WithRSA, crypto.SHA384},
	{x509.SHA512WithRSA, oidSignatureSHA512WithRSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, oidSignatureRSAPSS, crypto.SHA256},
	{x509.SHA384WithRSAPSS, oidSignatureRSAPSS, crypto.SHA384},
	{x509.SHA512WithRSAPSS, oidSignatureRSAPSS, crypto.SHA512},
	{x509.DSAWithSHA1, oidSignatureDSAWithSHA1, crypto.SHA1},
	{x509.DSAWithSHA256, oidSignatureDSAWithSHA256, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, crypto.SHA512},
	{x509.PureEd25519, oidSignatureEd25519, crypto.Hash(0)},
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

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func newSignatureAlgorithm(ai pkix.AlgorithmIdentifier) SignatureAlgorithm {
	sa := SignatureAlgorithm{
		OID: ai.Algorithm.String(),
	}

	if ai.Algorithm.Equal(oidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return sa
		}
	}

	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				sa.Name = details.algo.String()
				sa.algo = details.algo
				sa.hash = details.hash
			}
		}
		return sa
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return sa
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return sa
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return sa
	}

	switch {
	case params.Hash.Algorithm.Equal(oidSHA256) && params.SaltLength == 32:
		sa.Name = x509.SHA256WithRSAPSS.String()
		sa.algo = x509.SHA256WithRSAPSS
		sa.hash = crypto.SHA256
	case params.Hash.Algorithm.Equal(oidSHA384) && params.SaltLength == 48:
		sa.Name = x509.SHA384WithRSAPSS.String()
		sa.algo = x509.SHA384WithRSAPSS
		sa.hash = crypto.SHA384
	case params.Hash.Algorithm.Equal(oidSHA512) && params.SaltLength == 64:
		sa.Name = x509.SHA512WithRSAPSS.String()
		sa.algo = x509.SHA512WithRSAPSS
		sa.hash = crypto.SHA512
	}

	return sa
}
