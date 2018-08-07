package x509util

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
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
func LoadIdentityFromDisk(crtPath, keyPath string, pemOpts ...pemutil.Options) (*Identity, error) {
	crt, err := pemutil.ReadCertificate(crtPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pubPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	}

	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(pemOpts) == 0 {
		pemOpts = []pemutil.Options{pemutil.WithFilename(keyPath)}
	} else {
		pemOpts = append(pemOpts, pemutil.WithFilename(keyPath))
	}
	key, err := pemutil.Parse(keyBytes, pemOpts...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return NewIdentity(crt, pubPEM, key), nil
}
