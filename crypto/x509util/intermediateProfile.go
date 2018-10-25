package x509util

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/pkg/x509"
)

// DefaultIntermediateCertValidity is the default validity of a root certificate in the step PKI.
var DefaultIntermediateCertValidity = time.Hour * 24 * 365 * 10

// Intermediate implements the Profile for a intermediate certificate.
type Intermediate struct {
	base
}

// DefaultDuration returns the default Intermediate Certificate duration.
func (i *Intermediate) DefaultDuration() time.Duration {
	return DefaultIntermediateCertValidity
}

// NewIntermediateProfile returns a new intermediate x509 Certificate profile.
func NewIntermediateProfile(name string, iss *x509.Certificate, issPriv interface{}, withOps ...WithOption) (*Intermediate, error) {
	var (
		err       error
		notBefore = time.Now()
	)

	sub := &x509.Certificate{
		IsCA:      true,
		NotBefore: notBefore,
		// 10 year intermediate certificate validity.
		NotAfter: notBefore.Add(time.Hour * 24 * 365 * 10),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Issuer:                pkix.Name{CommonName: name},
		Subject:               pkix.Name{CommonName: name},
	}

	b, err := newBase(sub, iss, withOps...)
	if err != nil {
		return nil, err
	}

	if sub.SerialNumber == nil {
		// TODO figure out how to test rand w/out threading as another arg
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		sub.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
		// TODO error condition untested -- hard to test w/o mocking rand
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to generate serial number for "+
				"certificate with common name '%s'", name)
		}
	}

	i := &Intermediate{}
	fromBase(i, *b)
	i.SetIssuerPrivateKey(issPriv)
	return i, nil
}
