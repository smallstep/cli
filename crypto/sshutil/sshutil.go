package sshutil

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// NewCertSigner creates a new signer with the given certificate and private key.
func NewCertSigner(cert *ssh.Certificate, priv interface{}) (ssh.Signer, error) {
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "error creating signer")
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, errors.Wrap(err, "error creating signer")
	}
	return certSigner, nil
}

// ParseCertificate returns a certificate from the marshaled bytes.
func ParseCertificate(in []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(in)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.Errorf("error parsing certificate: %T is not a certificate", pub)
	}
	return cert, nil
}

// PublicKey returns the Go's crypto.PublicKey of an ssh.PublicKey.
func PublicKey(key ssh.PublicKey) (crypto.PublicKey, error) {
	_, in, ok := parseString(key.Marshal())
	if !ok {
		return nil, errors.New("public key is invalid")
	}

	switch key.Type() {
	case ssh.KeyAlgoRSA:
		return parseRSA(in)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return parseECDSA(in)
	case ssh.KeyAlgoED25519:
		return parseED25519(in)
	case ssh.KeyAlgoDSA:
		return parseDSA(in)
	default:
		return nil, errors.Errorf("public key %s is not supported", key.Type())
	}
}

// Fingerprint returns the key size, fingerprint, comment and algorithm of a
// public key.
func Fingerprint(in []byte) (string, error) {
	key, comment, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		return "", errors.Wrap(err, "error parsing public key")
	}
	if comment == "" {
		comment = "no comment"
	}

	var isCert bool
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
		isCert = true
	}

	var typ string
	var size int
	switch key.Type() {
	case ssh.KeyAlgoECDSA256:
		typ, size = "ECDSA", 256
	case ssh.KeyAlgoECDSA384:
		typ, size = "ECDSA", 384
	case ssh.KeyAlgoECDSA521:
		typ, size = "ECDSA", 521
	case ssh.KeyAlgoED25519:
		typ, size = "ED25519", 256
	case ssh.KeyAlgoRSA:
		typ = "RSA"
		_, in, ok := parseString(key.Marshal())
		if !ok {
			return "", errors.New("public key is invalid")
		}
		k, err := parseRSA(in)
		if err != nil {
			return "", err
		}
		size = 8 * k.Size()
	case ssh.KeyAlgoDSA:
		typ = "DSA"
		_, in, ok := parseString(key.Marshal())
		if !ok {
			return "", errors.New("public key is invalid")
		}
		k, err := parseDSA(in)
		if err != nil {
			return "", err
		}
		size = k.Parameters.P.BitLen()
	default:
		return "", errors.Errorf("public key %s is not supported", key.Type())
	}

	if isCert {
		typ = typ + "-CERT"
	}

	return fmt.Sprintf("%d %s %s (%s)", size, ssh.FingerprintSHA256(key), comment, typ), nil
}

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

// parseDSA parses an DSA key according to RFC 4253, section 6.6.
func parseDSA(in []byte) (*dsa.PublicKey, error) {
	var w struct {
		P, Q, G, Y *big.Int
		Rest       []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling public key")
	}

	param := dsa.Parameters{
		P: w.P,
		Q: w.Q,
		G: w.G,
	}
	return &dsa.PublicKey{
		Parameters: param,
		Y:          w.Y,
	}, nil
}

// parseRSA parses an RSA key according to RFC 4253, section 6.6.
func parseRSA(in []byte) (*rsa.PublicKey, error) {
	var w struct {
		E    *big.Int
		N    *big.Int
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling public key")
	}
	if w.E.BitLen() > 24 {
		return nil, errors.New("invalid public key: exponent too large")
	}
	e := w.E.Int64()
	if e < 3 || e&1 == 0 {
		return nil, errors.New("invalid public key: incorrect exponent")
	}

	var key rsa.PublicKey
	key.E = int(e)
	key.N = w.N
	return &key, nil
}

// parseECDSA parses an ECDSA key according to RFC 5656, section 3.1.
func parseECDSA(in []byte) (*ecdsa.PublicKey, error) {
	var w struct {
		Curve    string
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling public key")
	}

	key := new(ecdsa.PublicKey)

	switch w.Curve {
	case "nistp256":
		key.Curve = elliptic.P256()
	case "nistp384":
		key.Curve = elliptic.P384()
	case "nistp521":
		key.Curve = elliptic.P521()
	default:
		return nil, errors.Errorf("unsupported curve %s", w.Curve)
	}

	key.X, key.Y = elliptic.Unmarshal(key.Curve, w.KeyBytes)
	if key.X == nil || key.Y == nil {
		return nil, errors.New("invalid curve point")
	}

	return key, nil
}

func parseED25519(in []byte) (ed25519.PublicKey, error) {
	var w struct {
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling public key")
	}

	return ed25519.PublicKey(w.KeyBytes), nil
}
