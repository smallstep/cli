package x509

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
)

// Identity contains a public/private x509 certificate/key pair.
type Identity struct {
	Crt    *x509.Certificate
	CrtPem *pem.Block
	Key    interface{}
}

// NewIdentity returns a new Identity.
func NewIdentity(c *x509.Certificate, b *pem.Block, k interface{}) *Identity {
	return &Identity{
		Crt:    c,
		CrtPem: b,
		Key:    k,
	}
}

// LoadIdentityFromDisk load a public certificate and private key from disk.
func LoadIdentityFromDisk(crtPath, keyPath string, getPass func() (string, error)) (*Identity, error) {
	var (
		err          error
		caCert       *x509.Certificate
		caPrivateKey interface{}
		publicPem    *pem.Block
	)

	// load crt
	if caCert, publicPem, err = LoadCertificate(crtPath); err != nil {
		return nil, errors.WithStack(err)
	}

	// load private key
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if caPrivateKey, err = keys.LoadPrivateKey(keyBytes, getPass); err != nil {
		return nil, errors.WithStack(err)
	}

	return NewIdentity(caCert, publicPem, caPrivateKey), nil
}
