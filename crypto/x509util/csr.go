package x509util

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

// LoadCSRFromBytes loads a CSR given the ASN.1 DER format.
func LoadCSRFromBytes(der []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(der)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate request")
	}
	return csr, nil
}
