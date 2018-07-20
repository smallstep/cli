package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// DefaultPEMCipher is the default algorithm used when encrypting PEM blocks
// by the CA.
var (
	DefaultPEMCipher = x509.PEMCipherAES128
	// DefaultKeyType is the default type of a private key.
	DefaultKeyType = "EC"
	// DefaultKeySize is the default size (in # of bits) of a private key.
	DefaultKeySize = 2048
	// DefaultKeyCurve is the default curve of a private key.
	DefaultKeyCurve = "P-256"
)

// PublicKey extracts a public key from a private key.
func PublicKey(priv interface{}) (interface{}, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, errors.Errorf("unrecognized key type: %T", priv)
	}
}

// PublicPEM returns the public key in PEM block format.
func PublicPEM(pub interface{}) (*pem.Block, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &pem.Block{
		Bytes: pubBytes,
		Type:  "PUBLIC KEY",
	}, nil
}

// GenerateDefaultKey generates a public/private key pair using sane defaults
// for key type, curve, and size.
func GenerateDefaultKey() (interface{}, error) {
	return GenerateKey(DefaultKeyType, DefaultKeyCurve, DefaultKeySize)
}

// GenerateKey generates a key of the given type (kty).
func GenerateKey(kty, crv string, size int) (interface{}, error) {
	switch kty {
	case "EC":
		return generateECKey(crv)
	case "RSA":
		return generateRSAKey(size)
	case "OKP":
		return generateOKPKey(crv)
	case "oct":
		return generateOctKey(size)
	default:
		return nil, errors.Errorf("unrecognized key type: %s", kty)
	}
}

func generateECKey(crv string) (interface{}, error) {
	var c elliptic.Curve
	switch crv {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, errors.Errorf("invalid value for argument crv (crv: '%s')", crv)
	}

	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "error generating EC key")
	}

	return key, nil
}

func generateRSAKey(bits int) (interface{}, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Wrap(err, "error generating RSA key")
	}

	return key, nil
}

func generateOKPKey(crv string) (interface{}, error) {
	switch crv {
	case "Ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "error generating Ed25519 key")
		}

		return key, nil
	default:
		return nil, errors.Errorf("missing or invalid value for argument 'crv'. "+
			"expected 'Ed25519', but got '%s'", crv)
	}
}

func generateOctKey(size int) (interface{}, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, size)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return nil, err
		}
		result[i] = chars[num.Int64()]
	}
	return result, nil
}

// LoadPrivateKey loads a private key from a file.
// The first argument is the ASN.1 DER formatted private key.
// The second argument is a function that returns an encryption passphrase. If
// the private key is not encrypted the second arg can be nil or simply return
// an empty string. If the private key is encrypted then `getPass` should return
// the decryptor.
func LoadPrivateKey(bytes []byte, getPass func() (string, error)) (interface{}, error) {
	p, _ := pem.Decode(bytes)
	if p == nil {
		return nil, errors.Errorf("invalid key - key is not PEM formatted")
	}

	// The following block is focused on getting the decrypted key bytes
	// from the PEM block.
	// 1. Check if the key bytes were encrypted.
	//   a) encrypted: go to 2.
	//   b) not encrypted: hakuna mata (we don't have to do much).
	// 2. The key bytes are encrypted so we need a key to decrypt them.
	//   a) `pass` is empty therefore we request a decryption passphrase from
	//      stdin.
	// 3. Decrypt the key bytes using either a password from stdin or one
	//    passed in as an agument.
	var der []byte
	if x509.IsEncryptedPEMBlock(p) {
		if getPass == nil {
			return nil, errors.Errorf("private key needs a decryption passphrase")
		}
		pass, err := getPass()
		if err != nil {
			return nil, err
		}
		der, err = x509.DecryptPEMBlock(p, []byte(pass))
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		der = p.Bytes
	}

	var (
		err error
		key interface{}
	)
	switch p.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing RSA key")
		}
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing EC key")
		}
	default:
		return nil, errors.Errorf("unexpected key type: %s", p.Type)
	}
	return key, nil
}
