package pemutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	realx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/pkg/x509"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"golang.org/x/crypto/ed25519"
)

// DefaultEncCipher is the default algorithm used when encrypting sensitive
// data in the PEM format.
var DefaultEncCipher = x509.PEMCipherAES256

// context add options to the pem methods.
type context struct {
	filename   string
	password   []byte
	stepCrypto bool
}

// newContext initializes the context with a filename.
func newContext(name string) *context {
	return &context{filename: name}
}

// Options is the type to add attributes to the context.
type Options func(o *context) error

// WithFilename is a method that adds the given filename to the context.
func WithFilename(name string) Options {
	return func(ctx *context) error {
		ctx.filename = name
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

// WithStepCrypto returns cryptographic primitives of the modified step Crypto
// library.
func WithStepCrypto() Options {
	return func(ctx *context) error {
		ctx.stepCrypto = true
		return nil
	}
}

// ReadCertificate returns a *x509.Certificate from the given filename. It
// supports certificates formats PEM and DER.
func ReadCertificate(filename string) (*realx509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}

	// PEM format
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		crt, err := Read(filename)
		if err != nil {
			return nil, err
		}
		switch crt := crt.(type) {
		case *realx509.Certificate:
			return crt, nil
		default:
			return nil, errors.Errorf("error decoding PEM: file '%s' does not contain a certificate", filename)
		}
	}

	// DER format (binary)
	crt, err := realx509.ParseCertificate(b)
	return crt, errors.Wrapf(err, "error parsing %s", filename)
}

// ReadStepCertificate returns a *x509.Certificate from the given filename. It
// supports certificates formats PEM and DER.
func ReadStepCertificate(filename string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}

	// PEM format
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		crt, err := Read(filename, []Options{WithStepCrypto()}...)
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

// Parse returns the key or certificate PEM-encoded in the given bytes.
func Parse(b []byte, opts ...Options) (interface{}, error) {
	// Populate options
	ctx := newContext("PEM")
	for _, f := range opts {
		if err := f(ctx); err != nil {
			return nil, err
		}
	}

	block, rest := pem.Decode(b)
	switch {
	case block == nil:
		return nil, errors.Errorf("error decoding %s: is not a valid PEM encoded key", ctx.filename)
	case len(rest) > 0:
		return nil, errors.Errorf("error decoding %s: contains more than one key", ctx.filename)
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
		if ctx.stepCrypto {
			crt, err := x509.ParseCertificate(block.Bytes)
			return crt, errors.Wrapf(err, "error parsing %s", ctx.filename)
		}
		crt, err := realx509.ParseCertificate(block.Bytes)
		return crt, errors.Wrapf(err, "error parsing %s", ctx.filename)
	case "CERTIFICATE REQUEST":
		if ctx.stepCrypto {
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			return csr, errors.Wrapf(err, "error parsing %s", ctx.filename)
		}
		csr, err := realx509.ParseCertificateRequest(block.Bytes)
		return csr, errors.Wrapf(err, "error parsing %s", ctx.filename)
	default:
		return nil, errors.Errorf("error decoding %s: contains an unexpected header '%s'", ctx.filename, block.Type)
	}
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

// WithEncryption is a modifier for **Serialize** that will encrypt the
// PEM formatted data using the given key and a sane default cipher.
func WithEncryption(pass []byte) func(*pem.Block) error {
	return func(p *pem.Block) error {
		_p, err := x509.EncryptPEMBlock(rand.Reader, p.Type, p.Bytes, pass,
			DefaultEncCipher)
		if err != nil {
			return err
		}
		*p = *_p
		return nil
	}
}

// ToFile is modifier a for **Serialize** that will right the PEM formatted
// data to disk.
//
// NOTE: This modifier should be the last in the list of options passed to
// Serialize. Otherwise, transformation on the *pem.Block may not be completed
// at the time of encoding to disk.
func ToFile(f string, perm os.FileMode) func(*pem.Block) error {
	return func(p *pem.Block) error {
		err := utils.WriteFile(f, pem.EncodeToMemory(p), perm)
		if err != nil {
			return errs.FileError(err, f)
		}
		return nil
	}
}

// Serialize will serialize the input to a PEM formatted block and apply
// modifiers.
func Serialize(in interface{}, opts ...func(*pem.Block) error) (*pem.Block, error) {
	var p *pem.Block

	switch k := in.(type) {
	case *rsa.PrivateKey:
		p = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *rsa.PublicKey, *ecdsa.PublicKey:
		b, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}
	case ed25519.PrivateKey:
		var priv pkcs8
		priv.PrivateKey = append([]byte{4, 32}, k.Seed()...)[:34]
		priv.Algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		}
		b, err := asn1.Marshal(priv)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
	case ed25519.PublicKey:
		var pub publicKeyInfo
		pub.PublicKey = asn1.BitString{
			Bytes:     k,
			BitLength: 8 * ed25519.PublicKeySize,
		}
		pub.Algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		}
		b, err := asn1.Marshal(pub)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}
	case *x509.Certificate:
		p = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: k.Raw,
		}
	case *realx509.Certificate:
		p = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: k.Raw,
		}
	case *x509.CertificateRequest:
		p = &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: k.Raw,
		}
	case *realx509.CertificateRequest:
		p = &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: k.Raw,
		}
	default:
		return nil, errors.Errorf("cannot serialize type '%T', value '%v'", k, k)
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return p, nil
}
