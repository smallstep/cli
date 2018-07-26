package pem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/pkg/x509"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"
)

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

// Encrypted pkcs8
// Based on https://github.com/youmark/pkcs8
// MIT license
type prfParam struct {
	Algo      asn1.ObjectIdentifier
	NullParam asn1.RawValue
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	PrfParam       prfParam `asn1:"optional"`
}

type pbkdf2Algorithms struct {
	Algo         asn1.ObjectIdentifier
	PBKDF2Params pbkdf2Params
}

type pbkdf2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type pbes2Params struct {
	KeyDerivationFunc pbkdf2Algorithms
	EncryptionScheme  pbkdf2Encs
}

type encryptedlAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pbes2Params
}

type encryptedPrivateKeyInfo struct {
	Algo       encryptedlAlgorithmIdentifier
	PrivateKey []byte
}

// Algorithm Identifiers for Ed25519, Ed448, X25519 and X448 for use in the
// Internet X.509 Public Key Infrastructure
// https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
var (
	// oidX25519  = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// key derivation functions
	oidPKCS5PBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	// encryption
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES196CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESCBC    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidD3DESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
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
		return key, nil
	// Proof of concept for key agreement algorithm X25519.
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

// DecryptPEMBlock takes a password encrypted PEM block and the password used
// to encrypt it and returns a slice of decrypted DER encoded bytes.
//
// If the PEM blocks has the Proc-Type header set to "4,ENCRYPTED" it uses
// x509.DecryptPEMBlock to decrypt the block. If not it tries to decrypt the
// block using AES-128-CBC, AES-192-CBC, AES-256-CBC, DES, or 3DES using the
// key derived using PBKDF2 over the given password.
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return x509.DecryptPEMBlock(block, password)
	}

	// openssl
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		var pki encryptedPrivateKeyInfo
		if _, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
			return nil, err
		}

		if !pki.Algo.Algorithm.Equal(oidPBES2) {
			return nil, errors.New("unsupported encrypted PEM: only PBES2 is supported")
		}

		if !pki.Algo.Parameters.KeyDerivationFunc.Algo.Equal(oidPKCS5PBKDF2) {
			return nil, errors.New("unsupported encrypted PEM: only PBKDF2 is supported")
		}

		encParam := pki.Algo.Parameters.EncryptionScheme
		kdfParam := pki.Algo.Parameters.KeyDerivationFunc.PBKDF2Params

		iv := encParam.IV
		salt := kdfParam.Salt
		iter := kdfParam.IterationCount

		// pbkdf2 hash function
		keyHash := sha1.New
		if kdfParam.PrfParam.Algo.Equal(oidHMACWithSHA256) {
			keyHash = sha256.New
		}

		encryptedKey := pki.PrivateKey
		var symkey []byte
		var block cipher.Block
		var err error
		switch {
		// AES-128-CBC, AES-192-CBC, AES-256-CBC
		case encParam.EncryAlgo.Equal(oidAES128CBC):
			symkey = pbkdf2.Key(password, salt, iter, 16, keyHash)
			block, err = aes.NewCipher(symkey)
		case encParam.EncryAlgo.Equal(oidAES196CBC):
			symkey = pbkdf2.Key(password, salt, iter, 24, keyHash)
			block, err = aes.NewCipher(symkey)
		case encParam.EncryAlgo.Equal(oidAES256CBC):
			symkey = pbkdf2.Key(password, salt, iter, 32, keyHash)
			block, err = aes.NewCipher(symkey)
		// DES, TripleDES
		case encParam.EncryAlgo.Equal(oidDESCBC):
			symkey = pbkdf2.Key(password, salt, iter, 8, keyHash)
			block, err = des.NewCipher(symkey)
		case encParam.EncryAlgo.Equal(oidD3DESCBC):
			symkey = pbkdf2.Key(password, salt, iter, 24, keyHash)
			block, err = des.NewTripleDESCipher(symkey)
		default:
			return nil, errors.Errorf("unsupported encrypted PEM: unknown algorithm %v", encParam.EncryAlgo)
		}
		if err != nil {
			return nil, err
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(encryptedKey, encryptedKey)

		return encryptedKey, nil
	}

	return nil, errors.New("unsupported encrypted PEM")
}
