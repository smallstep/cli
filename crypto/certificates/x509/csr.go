package x509

import (
	"encoding/pem"
	"errors"

	"github.com/smallstep/cli/pkg/x509"
)

// LoadCSRFromBytes loads a CSR given the ASN.1 DER format.
func LoadCSRFromBytes(der []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(der)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing CSR")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
