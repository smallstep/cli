package x509util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func TestCSR_LoadCSRFromBytes(t *testing.T) {
	tests := map[string]struct {
		der func() ([]byte, error)
		err error
	}{
		"propagate pem decode error": {
			der: func() ([]byte, error) {
				return nil, nil
			},
			err: errors.New("failed to decode PEM block containing CSR"),
		},
		"propagate parse error": {
			der: func() ([]byte, error) {
				return []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyEU5ZhIhFn7v4bpMKlkz\ndmLCj9KfmqFWig29c6OzYoMUnbdodOmZ6RId/Gw5fnluH12eFxsItlXKDT4RPSm7\nm4D1sYgFmk88oo6z4XDuItDncoIg89jGK38OZ8A0gwEoy5JqukONGmAldzgzQyiq\nuzSNMeT1WO9zXCwOljcUio697M1kP/YN1Lp7n7YILVwdV8wQ2vyNKQK1M/5OZOFl\nlOqww4wsqLTDK0rfxp6LAVtczp1XdxbsnpdixrK38O+dHWe4IS5HhKLmmmdTfpFQ\nD3PIAXs/Naap/0+t0lsOplNPiF4BYyNBIqyyfm1o5ZQpGfmITKvDFZMBkQ2i2cou\nnQIDAQAB\n-----END PUBLIC KEY-----"), nil
			},
			err: errors.New("error parsing certificate request: asn1: structure error: tags don't match"),
		},
		"success": {
			der: func() ([]byte, error) {
				keypair, err := rsa.GenerateKey(rand.Reader, 4096)
				if err != nil {
					return nil, err
				}
				template := &x509.CertificateRequest{
					Subject: pkix.Name{
						Country:      []string{"Foo"},
						Organization: []string{"Smallstep"},
						CommonName:   "Bar",
					},
					SignatureAlgorithm: x509.SHA256WithRSA,
				}

				bytes, err := x509.CreateCertificateRequest(rand.Reader, template, keypair)
				if err != nil {
					return nil, err
				}

				return pem.EncodeToMemory(&pem.Block{
					Type:    "CSR",
					Headers: map[string]string{},
					Bytes:   bytes,
				}), nil
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			bytes, err := test.der()
			assert.FatalError(t, err)
			csr, err := LoadCSRFromBytes(bytes)

			if err != nil {
				if assert.NotNil(t, test.err) {
					assert.HasPrefix(t, err.Error(), test.err.Error())
				}
			} else {
				assert.Equals(t, csr.Subject.Country, []string{"Foo"})
				assert.Equals(t, csr.Subject.Organization, []string{"Smallstep"})
				assert.Equals(t, csr.Subject.CommonName, "Bar")
			}
		})
	}
}
