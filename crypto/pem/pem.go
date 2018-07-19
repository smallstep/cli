package pem

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/utils"
	"golang.org/x/crypto/ed25519"
)

// ReadCertificate returns a *x509.Certificate from the given filename. It
// supports certificates formats PEM and DER.
func ReadCertificate(filename string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}

	// PEM format
	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		crt, err := Read(filename)
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
func Parse(b []byte, filename string) (interface{}, error) {
	block, rest := pem.Decode(b)
	switch {
	case block == nil:
		return nil, errors.Errorf("error decoding PEM: file '%s' is not a valid PEM encoded key", filename)
	case len(rest) > 0:
		return nil, errors.Errorf("error decoding PEM: file '%s' contains more than one key", filename)
	}

	// PEM is encrypted: ask for password
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		pass, err := utils.ReadPassword(fmt.Sprintf("Please enter the password to decrypt %s: ", filename))
		if err != nil {
			return nil, err
		}

		block.Bytes, err = x509.DecryptPEMBlock(block, pass)
		if err != nil {
			return nil, errors.Wrapf(err, "error decrypting %s", filename)
		}
	}

	switch block.Type {
	case "PUBLIC KEY":
		pub, err := ParsePKIXPublicKey(block.Bytes)
		return pub, errors.Wrapf(err, "error parsing %s", filename)
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return priv, errors.Wrapf(err, "error parsing %s", filename)
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		return priv, errors.Wrapf(err, "error parsing %s", filename)
	case "PRIVATE KEY", "OPENSSH PRIVATE KEY":
		priv, err := ParsePKCS8PrivateKey(block.Bytes)
		return priv, errors.Wrapf(err, "error parsing %s", filename)
	case "CERTIFICATE":
		crt, err := x509.ParseCertificate(b)
		return crt, errors.Wrapf(err, "error parsing %s", filename)
	default:
		return nil, errors.Errorf("error decoding PEM: file '%s' contains an unexpected header '%s'", filename, block.Type)
	}
}

// Read returns the key or certificated encoded in the given PEM encoded
// file. If the file is encrypted it will ask for a password and it will try
// to decrypt it.
//
// Supported keys algorithms are RSA and EC. Supported standards for private
// keys are PKCS#1, PKCS#8, RFC5915 for EC, and base64-encoded DER for
// certificates and public keys.
func Read(filename string) (interface{}, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}

	return Parse(b, filename)
}

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algo      pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// Algorithm Identifiers for Ed25519, Ed448, X25519 and X448 for use in the
// Internet X.509 Public Key Infrastructure
// https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
var (
	// oidX25519  = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// ParsePKCS8PrivateKey parses an unencrypted, PKCS#8 private key. See RFC
// 5208.
//
// Supported key types include RSA, ECDSA, and Ed25519. Unknown key types
// result in an error.
//
// On success, key will be of type *rsa.PrivateKey, *ecdsa.PublicKey, or
// ed25519.PrivateKey.
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}

	switch {
	case privKey.Algo.Algorithm.Equal(oidEd25519):
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, privKey.PrivateKey[2:])
		key = ed25519.NewKeyFromSeed(seed)
		kk := key.(ed25519.PrivateKey)
		fmt.Fprintf(os.Stderr, "% x\n% x\n", kk, kk.Public())
		return key, nil
	// Prove of concept for key agreement algorithm X25519.
	// A real implementation would use their own types.
	//
	// case privKey.Algo.Algorithm.Equal(oidX25519):
	// 	k := make([]byte, ed25519.PrivateKeySize)
	// 	var pub, priv [32]byte
	// 	copy(priv[:], privKey.PrivateKey[2:])
	// 	curve25519.ScalarBaseMult(&pub, &priv)
	// 	copy(k, priv[:])
	// 	copy(k[32:], pub[:])
	// 	key = ed25519.PrivateKey(k)
	// 	return key, nil
	default:
		return x509.ParsePKCS8PrivateKey(der)
	}
}

// ParsePKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
//
// Supported key types include RSA, DSA, ECDSA, and Ed25519. Unknown key types
// result in an error.
//
// On success, pub will be of type *rsa.PublicKey, *dsa.PublicKey,
// *ecdsa.PublicKey, or ed25519.PublicKey.
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	switch {
	case pki.Algo.Algorithm.Equal(oidEd25519):
		pub = ed25519.PublicKey(pki.PublicKey.Bytes)
		return pub, nil
	// Prove of concept for key agreement algorithm X25519.
	// A real implementation would use their own types.
	//
	// case pki.Algo.Algorithm.Equal(oidX25519):
	// 	pub = ed25519.PublicKey(pki.PublicKey.Bytes)
	// 	fmt.Fprintf(os.Stderr, "% x\n", pub)
	// 	return pub, nil
	default:
		return x509.ParsePKIXPublicKey(derBytes)
	}
}
