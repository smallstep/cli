package x509

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	spem "github.com/smallstep/cli/crypto/pem"
	"github.com/smallstep/cli/utils"
	"golang.org/x/crypto/ed25519"
)

// Profile is an interface that certificate profiles (e.g. leaf,
// intermediate, root) must implement.
type Profile interface {
	Issuer() *x509.Certificate
	Subject() *x509.Certificate
	SubjectPrivateKey() interface{}
	SubjectPublicKey() interface{}
	SetIssuer(*x509.Certificate)
	SetSubject(*x509.Certificate)
	SetSubjectPrivateKey(interface{})
	SetSubjectPublicKey(interface{})
	SetIssuerPrivateKey(interface{})
	CreateCertificate() ([]byte, error)
	GenerateKeyPair(string, string, int) error
}

type base struct {
	iss     *x509.Certificate
	sub     *x509.Certificate
	subPub  interface{}
	subPriv interface{}
	issPriv interface{}
}

// WithOption is a modifier function on base.
type WithOption func(Profile) error

// GenerateKeyPair returns a Profile modifier that generates a public/private
// key pair for a profile.
func GenerateKeyPair(kty, crv string, size int) WithOption {
	return func(p Profile) error {
		return p.GenerateKeyPair(kty, crv, size)
	}
}

// WithPublicKey returns a Profile modifier that sets the public key for a profile.
func WithPublicKey(pub interface{}) WithOption {
	return func(p Profile) error {
		p.SetSubjectPublicKey(pub)
		return nil
	}
}

// WithSubject returns a Profile modifier that sets the Subject for a x509
// Certificate.
func WithSubject(sub pkix.Name) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.Subject = sub
		return nil
	}
}

// WithIssuer returns a Profile modifier that sets the Subject for a x509
// Certificate.
func WithIssuer(iss pkix.Name) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.Issuer = iss
		return nil
	}
}

// WithNotBeforeAfter returns a Profile modifier that sets the `NotBefore` and
// `NotAfter` attributes of the subject x509 Certificate.
func WithNotBeforeAfter(nb, na time.Time) WithOption {
	return func(p Profile) error {
		crt := p.Subject()
		crt.NotBefore = nb
		crt.NotAfter = na
		return nil
	}
}

// WithHosts returns a Profile modifier which sets the DNS Names and IP Addresses
// that will be bound to the subject Certificate.
//
// `hosts` should be a comma separated string of DNS Names and IP Addresses.
// e.g. `127.0.0.1,internal.smallstep.com,blog.smallstep.com,1.1.1.1`.
func WithHosts(hosts string) WithOption {
	return func(p Profile) error {
		hostsL := strings.Split(hosts, ",")
		crt := p.Subject()
		for _, h := range hostsL {
			if h == "" {
				continue
			} else if ip := net.ParseIP(h); ip != nil {
				crt.IPAddresses = append(crt.IPAddresses, ip)
			} else {
				crt.DNSNames = append(crt.DNSNames, h)
			}
		}

		return nil
	}
}

// newBase generates a new base profile.
//
// If the public/private key pair of the subject identity are not set by
// the optional modifiers then a pair will be generated using sane defaults.
func newBase(sub, iss *x509.Certificate, withOps ...WithOption) (*base, error) {
	if sub == nil {
		return nil, errors.Errorf("subject certificate cannot be nil")
	}
	if iss == nil {
		return nil, errors.Errorf("issuing certificate cannot be nil")
	}

	var (
		err error
		b   = &base{}
	)
	b.SetSubject(sub)
	b.SetIssuer(iss)

	for _, op := range withOps {
		if err := op(b); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if b.SubjectPublicKey() == nil {
		if err := b.GenerateDefaultKeyPair(); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if b.sub.SubjectKeyId == nil {
		var pubBytes []byte
		switch pk := b.SubjectPublicKey().(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			pubBytes, err = x509.MarshalPKIXPublicKey(b.SubjectPublicKey())
			if err != nil {
				return nil, errors.Wrapf(err, "failed to marshal public key to bytes")
			}
		case ed25519.PublicKey:
			pubBytes = []byte(pk)
		default:
			return nil, errors.Errorf("Cannot calculate SubjectKeyId for key of type %T", pk)
		}
		hash := sha1.Sum(pubBytes)
		b.sub.SubjectKeyId = hash[:] // takes slice over the whole array
	}

	if b.sub.SerialNumber == nil {
		// TODO figure out how to test rand w/out threading as another arg
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		b.sub.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
		// TODO error condition untested -- hard to test w/o mocking rand
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to generate serial number for "+
				"certificate with common name '%s'", sub.Subject.CommonName)
		}
	}

	return b, nil
}

func fromBase(profile Profile, b base) {
	profile.SetSubject(b.Subject())
	profile.SetIssuer(b.Issuer())
	profile.SetSubjectPublicKey(b.SubjectPublicKey())
	profile.SetSubjectPrivateKey(b.SubjectPrivateKey())
	profile.SetIssuerPrivateKey(b.issPriv)
}

func (b *base) Issuer() *x509.Certificate {
	return b.iss
}

func (b *base) Subject() *x509.Certificate {
	return b.sub
}

func (b *base) SubjectPrivateKey() interface{} {
	return b.subPriv
}

func (b *base) SubjectPublicKey() interface{} {
	return b.subPub
}

func (b *base) SetIssuer(iss *x509.Certificate) {
	b.iss = iss
}

func (b *base) SetSubject(sub *x509.Certificate) {
	b.sub = sub
}

func (b *base) SetSubjectPrivateKey(priv interface{}) {
	b.subPriv = priv
}

func (b *base) SetIssuerPrivateKey(priv interface{}) {
	b.issPriv = priv
}

func (b *base) SetSubjectPublicKey(pub interface{}) {
	b.subPub = pub
}

func (b *base) GenerateKeyPair(kty, crv string, size int) error {
	pub, priv, err := keys.GenerateKeyPair(kty, crv, size)
	if err != nil {
		return err
	}
	b.SetSubjectPublicKey(pub)
	b.SetSubjectPrivateKey(priv)
	return nil
}

func (b *base) GenerateDefaultKeyPair() error {
	pub, priv, err := keys.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}
	b.SetSubjectPublicKey(pub)
	b.SetSubjectPrivateKey(priv)
	return nil
}

// CreateCertificate creates an x509 Certificate using the configuration stored
// in the profile.
func (b *base) CreateCertificate() ([]byte, error) {
	if b.SubjectPublicKey() == nil {
		return nil, errors.Errorf("Profile does not have subject public key. Need to call 'profile.GenKeys(...)' or use setters to populate keys")
	}
	if b.issPriv == nil {
		return nil, errors.Errorf("Profile does not have issuer private key. Use setters to populate this field.")
	}
	bytes, err := x509.CreateCertificate(rand.Reader, b.Subject(), b.Issuer(),
		b.SubjectPublicKey(), b.issPriv)
	return bytes, errors.WithStack(err)
}

// Create Certificate from profile and write the certificate and private key
// to disk.
func (b *base) CreateWriteCertificate(crtOut, keyOut, pass string) ([]byte, error) {
	crtBytes, err := b.CreateCertificate()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err := utils.WriteFile(crtOut, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}), 0600); err != nil {
		return nil, errors.WithStack(err)
	}

	_, err = spem.Serialize(b.SubjectPrivateKey(),
		spem.WithEncryption(pass), spem.ToFile(keyOut, 0600))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return crtBytes, nil
}
