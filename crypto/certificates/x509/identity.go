package x509

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
	spem "github.com/smallstep/cli/crypto/pem"
	"github.com/smallstep/cli/pkg/x509"
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

// LoadIdentityFromDisk load a public certificate and private key (both in PEM
// format) from disk.
func LoadIdentityFromDisk(crtPath, keyPath string, pemOpts ...spem.Options) (*Identity, error) {
	// load crt
	crt, pubPEM, err := LoadCertificate(crtPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// load private key
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	key, err := spem.Parse(keyBytes, pemOpts...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return NewIdentity(crt, pubPEM, key), nil
}
