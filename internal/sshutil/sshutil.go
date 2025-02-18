package sshutil

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // support deprecated algorithms.
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli/internal/cast"
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
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return parseECDSA(in)
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519:
		return parseED25519(in)
	case ssh.KeyAlgoDSA:
		return parseDSA(in)
	default:
		return nil, errors.Errorf("public key %s is not supported", key.Type())
	}
}

func publicKeyTypeAndSize(key ssh.PublicKey) (string, int, error) {
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
	case ssh.KeyAlgoSKECDSA256:
		typ, size = "SK-ECDSA", 256
	case ssh.KeyAlgoED25519:
		typ, size = "ED25519", 256
	case ssh.KeyAlgoSKED25519:
		typ, size = "SK-ED25519", 256
	case ssh.KeyAlgoRSA:
		typ = "RSA"
		_, in, ok := parseString(key.Marshal())
		if !ok {
			return "", 0, errors.New("public key is invalid")
		}
		k, err := parseRSA(in)
		if err != nil {
			return "", 0, err
		}
		size = 8 * k.Size()
	case ssh.KeyAlgoDSA:
		typ = "DSA"
		_, in, ok := parseString(key.Marshal())
		if !ok {
			return "", 0, errors.New("public key is invalid")
		}
		k, err := parseDSA(in)
		if err != nil {
			return "", 0, err
		}
		size = k.Parameters.P.BitLen()
	default:
		return "", 0, errors.Errorf("public key %s is not supported", key.Type())
	}

	if isCert {
		typ += "-CERT"
	}

	return typ, size, nil
}

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if cast.Uint32(len(in)) < length {
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
		return nil, errors.Wrap(err, "error unmarshaling public key")
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
		return nil, errors.Wrap(err, "error unmarshaling public key")
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
//
// This function is based on the one in golang.org/x/crypto/ssh.
func parseECDSA(in []byte) (*ecdsa.PublicKey, error) {
	var w struct {
		Name  string
		Curve string
		Key   []byte
	}

	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling public key")
	}

	var (
		key   *ecdh.PublicKey
		curve elliptic.Curve
		size  int
		err   error
	)

	switch w.Curve {
	case "nistp256":
		curve = elliptic.P256()
		key, err = ecdh.P256().NewPublicKey(w.Key)
		size = 32
	case "nistp384":
		curve = elliptic.P384()
		key, err = ecdh.P384().NewPublicKey(w.Key)
		size = 48
	case "nistp521":
		curve = elliptic.P521()
		key, err = ecdh.P521().NewPublicKey(w.Key)
		size = 66
	default:
		return nil, errors.Errorf("unsupported curve %s", w.Curve)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(key.Bytes()[1 : size+1]),
		Y:     big.NewInt(0).SetBytes(key.Bytes()[size+1:]),
	}, nil
}

func parseED25519(in []byte) (ed25519.PublicKey, error) {
	var w struct {
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling public key")
	}

	return ed25519.PublicKey(w.KeyBytes), nil
}
