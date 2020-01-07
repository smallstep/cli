package pemutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"golang.org/x/crypto/ssh"
)

// DefaultEncCipher is the default algorithm used when encrypting sensitive
// data in the PEM format.
var DefaultEncCipher = x509.PEMCipherAES256

// context add options to the pem methods.
type context struct {
	filename   string
	perm       os.FileMode
	password   []byte
	pkcs8      bool
	firstBlock bool
}

// newContext initializes the context with a filename.
func newContext(name string) *context {
	return &context{
		filename: name,
		perm:     0600,
	}
}

// apply the context options and return the first error if exists.
func (c *context) apply(opts []Options) error {
	for _, fn := range opts {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

// Options is the type to add attributes to the context.
type Options func(o *context) error

// WithFilename is a method that adds the given filename to the context.
func WithFilename(name string) Options {
	return func(ctx *context) error {
		ctx.filename = name
		// Default perm mode if not set
		if ctx.perm == 0 {
			ctx.perm = 0600
		}
		return nil
	}
}

// ToFile is a method that adds the given filename and permissions to the
// context. It is used in the Serialize to store PEM in disk.
func ToFile(name string, perm os.FileMode) Options {
	return func(ctx *context) error {
		ctx.filename = name
		ctx.perm = perm
		return nil
	}
}

// WithPassword is a method that adds the given password to the context.
func WithPassword(pass []byte) Options {
	return func(ctx *context) error {
		ctx.password = pass
		return nil
	}
}

// WithPasswordFile is a method that adds the password in a file to the context.
func WithPasswordFile(filename string) Options {
	return func(ctx *context) error {
		b, err := utils.ReadPasswordFromFile(filename)
		if err != nil {
			return err
		}
		ctx.password = b
		return nil
	}
}

// WithPasswordPrompt ask the user for a password and adds it to the context.
func WithPasswordPrompt(prompt string) Options {
	return func(ctx *context) error {
		b, err := ui.PromptPassword(prompt, ui.WithValidateNotEmpty())
		if err != nil {
			return err
		}
		ctx.password = b
		return nil
	}
}

// WithPKCS8 with v set to true returns an option used in the Serialize method
// to use the PKCS#8 encoding form on the private keys. With v set to false
// default form will be used.
func WithPKCS8(v bool) Options {
	return func(ctx *context) error {
		ctx.pkcs8 = v
		return nil
	}
}

// WithFirstBlock will avoid failing if a PEM contains more than one block or
// certificate and it will only look at the first.
func WithFirstBlock() Options {
	return func(ctx *context) error {
		ctx.firstBlock = true
		return nil
	}
}

// ReadCertificate returns a *x509.Certificate from the given filename. It
// supports certificates formats PEM and DER.
func ReadCertificate(filename string, opts ...Options) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}

	// PEM format
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		var crt interface{}
		crt, err = Read(filename, opts...)
		if err != nil {
			return nil, err
		}
		switch crt := crt.(type) {
		case *x509.Certificate:
			return crt, nil
		default:
			return nil, errors.Errorf("error decoding PEM: file '%s' does not contain a certificate", filename)
		}
	}

	// DER format (binary)
	crt, err := x509.ParseCertificate(b)
	return crt, errors.Wrapf(err, "error parsing %s", filename)
}

// ReadCertificateBundle returns a list of *x509.Certificate from the given
// filename. It supports certificates formats PEM and DER. If a DER-formatted
// file is given only one certificate will be returned.
func ReadCertificateBundle(filename string) ([]*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}

	// PEM format
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		var block *pem.Block
		var bundle []*x509.Certificate
		for len(b) > 0 {
			block, b = pem.Decode(b)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil, errors.Errorf("error decoding PEM: file '%s' is not a certificate bundle", filename)
			}
			var crt *x509.Certificate
			crt, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, "error parsing %s", filename)
			}
			bundle = append(bundle, crt)
		}
		if len(b) > 0 {
			return nil, errors.Errorf("error decoding PEM: file '%s' contains unexpected data", filename)
		}
		return bundle, nil
	}

	// DER format (binary)
	crt, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", filename)
	}
	return []*x509.Certificate{crt}, nil
}

// Parse returns the key or certificate PEM-encoded in the given bytes.
func Parse(b []byte, opts ...Options) (interface{}, error) {
	// Populate options
	ctx := newContext("PEM")
	if err := ctx.apply(opts); err != nil {
		return nil, err
	}

	block, rest := pem.Decode(b)
	switch {
	case block == nil:
		return nil, errors.Errorf("error decoding %s: not a valid PEM encoded block", ctx.filename)
	case len(rest) > 0 && !ctx.firstBlock:
		return nil, errors.Errorf("error decoding %s: contains more than one PEM endoded block", ctx.filename)
	}

	// PEM is encrypted: ask for password
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" || block.Type == "ENCRYPTED PRIVATE KEY" {
		var err error
		var pass []byte

		if len(ctx.password) > 0 {
			pass = ctx.password
		} else {
			pass, err = ui.PromptPassword(fmt.Sprintf("Please enter the password to decrypt %s", ctx.filename))
			if err != nil {
				return nil, err
			}
		}

		block.Bytes, err = DecryptPEMBlock(block, pass)
		if err != nil {
			return nil, errors.Wrapf(err, "error decrypting %s", ctx.filename)
		}
	}

	switch block.Type {
	case "PUBLIC KEY":
		pub, err := ParsePKIXPublicKey(block.Bytes)
		return pub, errors.Wrapf(err, "error parsing %s", ctx.filename)
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return priv, errors.Wrapf(err, "error parsing %s", ctx.filename)
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		return priv, errors.Wrapf(err, "error parsing %s", ctx.filename)
	case "PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		priv, err := ParsePKCS8PrivateKey(block.Bytes)
		return priv, errors.Wrapf(err, "error parsing %s", ctx.filename)
	case "CERTIFICATE":
		crt, err := x509.ParseCertificate(block.Bytes)
		return crt, errors.Wrapf(err, "error parsing %s", ctx.filename)
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		return csr, errors.Wrapf(err, "error parsing %s", ctx.filename)
	default:
		return nil, errors.Errorf("error decoding %s: contains an unexpected header '%s'", ctx.filename, block.Type)
	}
}

// ParseKey returns the key or the public key of a certificate or certificate
// signing request in the given PEM-encoded bytes.
func ParseKey(b []byte, opts ...Options) (interface{}, error) {
	k, err := Parse(b, opts...)
	if err != nil {
		return nil, err
	}
	return keys.ExtractKey(k)
}

// Read returns the key or certificate encoded in the given PEM file.
// If the file is encrypted it will ask for a password and it will try
// to decrypt it.
//
// Supported keys algorithms are RSA and EC. Supported standards for private
// keys are PKCS#1, PKCS#8, RFC5915 for EC, and base64-encoded DER for
// certificates and public keys.
func Read(filename string, opts ...Options) (interface{}, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}

	// force given filename
	opts = append(opts, WithFilename(filename))
	return Parse(b, opts...)
}

// Serialize will serialize the input to a PEM formatted block and apply
// modifiers.
func Serialize(in interface{}, opts ...Options) (*pem.Block, error) {
	ctx := new(context)
	if err := ctx.apply(opts); err != nil {
		return nil, err
	}

	var p *pem.Block
	switch k := in.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		b, err := MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}
	case *rsa.PrivateKey:
		if ctx.pkcs8 {
			b, err := MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, err
			}
			p = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: b,
			}
		} else {
			p = &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k),
			}
		}
	case *ecdsa.PrivateKey:
		if ctx.pkcs8 {
			b, err := MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, err
			}
			p = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: b,
			}
		} else {
			b, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, errors.Wrap(err, "failed to marshal private key")
			}
			p = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: b,
			}
		}
	case ed25519.PrivateKey: // force the use of pkcs8
		ctx.pkcs8 = true
		b, err := MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		p = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
	case *x509.Certificate:
		p = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: k.Raw,
		}
	case *x509.CertificateRequest:
		p = &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: k.Raw,
		}
	default:
		return nil, errors.Errorf("cannot serialize type '%T', value '%v'", k, k)
	}

	// Apply options on the PEM blocks.
	if ctx.password != nil {
		if _, ok := in.(crypto.PrivateKey); ok && ctx.pkcs8 {
			var err error
			p, err = EncryptPKCS8PrivateKey(rand.Reader, p.Bytes, ctx.password, DefaultEncCipher)
			if err != nil {
				return nil, err
			}
		} else {
			var err error
			p, err = x509.EncryptPEMBlock(rand.Reader, p.Type, p.Bytes, ctx.password, DefaultEncCipher)
			if err != nil {
				return nil, errors.Wrap(err, "failed to serialize to PEM")
			}
		}
	}

	if ctx.filename != "" {
		if err := utils.WriteFile(ctx.filename, pem.EncodeToMemory(p), ctx.perm); err != nil {
			return nil, errs.FileError(err, ctx.filename)
		}
	}

	return p, nil
}

// ParseDER parses the given DER-encoded bytes and results the public or private
// key encoded.
func ParseDER(b []byte) (interface{}, error) {
	// Try private keys
	key, err := ParsePKCS8PrivateKey(b)
	if err != nil {
		if key, err = x509.ParseECPrivateKey(b); err != nil {
			key, err = x509.ParsePKCS1PrivateKey(b)
		}
	}

	// Try public key
	if err != nil {
		if key, err = ParsePKIXPublicKey(b); err != nil {
			if key, err = x509.ParsePKCS1PublicKey(b); err != nil {
				return nil, errors.New("error decoding DER; bad format")
			}
		}
	}

	return key, nil
}

// ParseSSH parses parses a public key from an authorized_keys file used in
// OpenSSH according to the sshd(8) manual page.
func ParseSSH(b []byte) (interface{}, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing OpenSSH key")
	}

	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}

	switch key.Type() {
	case ssh.KeyAlgoRSA:
		var w struct {
			Name string
			E    *big.Int
			N    *big.Int
		}
		if err := ssh.Unmarshal(key.Marshal(), &w); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling key")
		}

		if w.E.BitLen() > 24 {
			return nil, errors.New("error unmarshaling key: exponent too large")
		}
		e := w.E.Int64()
		if e < 3 || e&1 == 0 {
			return nil, errors.New("error unmarshaling key: incorrect exponent")
		}

		key := new(rsa.PublicKey)
		key.E = int(e)
		key.N = w.N
		return key, nil

	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		var w struct {
			Name     string
			ID       string
			KeyBytes []byte
		}
		if err := ssh.Unmarshal(key.Marshal(), &w); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling key")
		}

		key := new(ecdsa.PublicKey)
		switch w.Name {
		case ssh.KeyAlgoECDSA256:
			key.Curve = elliptic.P256()
		case ssh.KeyAlgoECDSA384:
			key.Curve = elliptic.P384()
		case ssh.KeyAlgoECDSA521:
			key.Curve = elliptic.P521()
		default:
			return nil, errors.Errorf("unsupported ecdsa curve %s", w.Name)
		}

		key.X, key.Y = elliptic.Unmarshal(key.Curve, w.KeyBytes)
		if key.X == nil || key.Y == nil {
			return nil, errors.New("invalid ecdsa curve point")
		}
		return key, nil

	case ssh.KeyAlgoED25519:
		var w struct {
			Name     string
			KeyBytes []byte
		}
		if err := ssh.Unmarshal(key.Marshal(), &w); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling key")
		}
		return ed25519.PublicKey(w.KeyBytes), nil

	case ssh.KeyAlgoDSA:
		return nil, errors.Errorf("step does not support DSA keys")

	default:
		return nil, errors.Errorf("unsupported key type %T", key)
	}
}
