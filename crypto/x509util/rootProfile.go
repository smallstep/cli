package x509util

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/pkg/x509"
)

// DefaultRootCertValidity is the default validity of a root certificate in the step PKI.
var DefaultRootCertValidity = time.Hour * 24 * 365 * 10

// Root implements the Profile for a root certificate.
type Root struct {
	base
}

// DefaultDuration returns the default Root Certificate duration.
func (r *Root) DefaultDuration() time.Duration {
	return DefaultRootCertValidity
}

// NewRootProfile returns a new root x509 Certificate profile.
func NewRootProfile(name string, withOps ...WithOption) (*Root, error) {
	crt, err := defaultRootTemplate(name)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	b, err := newBase(crt, crt, withOps...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := &Root{}
	fromBase(r, *b)
	r.SetIssuerPrivateKey(r.SubjectPrivateKey())
	return r, nil
}

// NewRootProfileWithTemplate returns a new root x509 Certificate profile.
func NewRootProfileWithTemplate(crt *x509.Certificate, withOps ...WithOption) (*Root, error) {
	b, err := newBase(crt, crt, withOps...)
	if err != nil {
		return nil, err
	}

	r := &Root{}
	fromBase(r, *b)
	r.SetIssuerPrivateKey(r.SubjectPrivateKey())
	return r, nil
}

func defaultRootTemplate(cn string) (*x509.Certificate, error) {
	var (
		err       error
		notBefore = time.Now()
	)

	ct := &x509.Certificate{
		IsCA:      true,
		NotBefore: notBefore,
		// 10 year root certificate validity.
		NotAfter: notBefore.Add(time.Hour * 24 * 365 * 10),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		Issuer:                pkix.Name{CommonName: cn},
		Subject:               pkix.Name{CommonName: cn},
	}

	// TODO figure out how to test rand w/out threading as another arg
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	ct.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	// TODO error condition untested -- hard to test w/o mocking rand
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to generate serial number for "+
			"certificate with common name '%s'", cn)
	}

	return ct, nil

}
