package x509

import (
	"crypto/x509/pkix"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/pkg/x509"
)

// Leaf implements the Profile for a leaf certificate.
type Leaf struct {
	base
}

// NewLeafProfileWithTemplate returns a new leaf x509 Certificate Profile with
// Subject Certificate set to the value of the template argument.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the Subject Certificate parameter.
func NewLeafProfileWithTemplate(sub *x509.Certificate, iss *x509.Certificate, issPriv interface{}, withOps ...WithOption) (*Leaf, error) {
	withOps = append(withOps, WithPublicKey(sub.PublicKey))
	b, err := newBase(sub, iss, withOps...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	l := &Leaf{}
	fromBase(l, *b)
	l.SetIssuerPrivateKey(issPriv)
	return l, nil
}

// NewLeafProfile returns a new leaf x509 Certificate profile.
// A new public/private key pair will be generated for the Profile if
// not set in the `withOps` profile modifiers.
func NewLeafProfile(cn string, iss *x509.Certificate, issPriv interface{}, withOps ...WithOption) (*Leaf, error) {
	sub, err := defaultLeafTemplate(pkix.Name{CommonName: cn}, iss.Subject)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	b, err := newBase(sub, iss, withOps...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	l := &Leaf{}
	fromBase(l, *b)
	l.SetIssuerPrivateKey(issPriv)
	return l, nil
}

// NewLeafProfileWithCSR returns a new leaf x509 Certificate Profile with
// Subject Certificate fields populated directly from the CSR.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the CSR.
func NewLeafProfileWithCSR(csr *x509.CertificateRequest, iss *x509.Certificate, issPriv interface{}, withOps ...WithOption) (*Leaf, error) {
	if csr.PublicKey == nil {
		return nil, errors.Errorf("CSR must have PublicKey")
	}
	withOps = append(withOps, WithPublicKey(csr.PublicKey))

	sub, err := defaultLeafTemplate(csr.Subject, iss.Subject)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sub.Extensions = csr.Extensions
	sub.ExtraExtensions = csr.ExtraExtensions
	sub.DNSNames = csr.DNSNames
	sub.EmailAddresses = csr.EmailAddresses
	sub.IPAddresses = csr.IPAddresses
	sub.URIs = csr.URIs

	b, err := newBase(sub, iss, withOps...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	l := &Leaf{}
	fromBase(l, *b)
	l.SetIssuerPrivateKey(issPriv)
	return l, nil
}

func defaultLeafTemplate(sub pkix.Name, iss pkix.Name) (*x509.Certificate, error) {
	notBefore := time.Now()

	ct := &x509.Certificate{
		IsCA:      false,
		NotBefore: notBefore,
		// 1 Day Leaf Certificate validity.
		NotAfter: notBefore.Add(time.Hour * 24),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		Issuer:                iss,
		Subject:               sub,
	}

	return ct, nil
}
