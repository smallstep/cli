// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pemutil

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/pkg/bcrypt_pbkdf"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"go.step.sm/cli-utils/errs"
	"golang.org/x/crypto/ssh"
)

const (
	sshMagic             = "openssh-key-v1\x00"
	sshDefaultKdf        = "bcrypt"
	sshDefaultCiphername = "aes256-ctr"
	sshDefaultKeyLength  = 32
	sshDefaultSaltLength = 16
	sshDefaultRounds     = 16
)

type openSSHPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type openSSHPrivateKeyBlock struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

// ParseOpenSSHPrivateKey parses a private key in OpenSSH PEM format.
//
// Implemented based on the documentation at
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
//
// This method is based on the implementation at
// https://github.com/golang/crypto/blob/master/ssh/keys.go
func ParseOpenSSHPrivateKey(key []byte, opts ...Options) (crypto.PrivateKey, error) {
	// Populate options
	ctx := newContext("PEM")
	if err := ctx.apply(opts); err != nil {
		return nil, err
	}

	if len(key) < len(sshMagic) || string(key[:len(sshMagic)]) != sshMagic {
		return nil, errors.New("invalid openssh private key format")
	}
	remaining := key[len(sshMagic):]

	var w openSSHPrivateKey
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return nil, err
	}

	if w.KdfName != "none" || w.CipherName != "none" {
		if w.KdfName != sshDefaultKdf {
			return nil, errors.Errorf("cannot decode encrypted private keys with %s key derivative function", w.KdfName)
		}
		if w.CipherName != sshDefaultCiphername {
			return nil, errors.Errorf("cannot decode %s encrypted private keys", w.CipherName)
		}

		// Read kdf options.
		buf := bytes.NewReader([]byte(w.KdfOpts))

		var saltLength uint32
		if err := binary.Read(buf, binary.BigEndian, &saltLength); err != nil {
			return nil, errors.New("cannot decode encrypted private keys: bad format")
		}

		salt := make([]byte, saltLength)
		if err := binary.Read(buf, binary.BigEndian, &salt); err != nil {
			return nil, errors.New("cannot decode encrypted private keys: bad format")
		}

		var rounds uint32
		if err := binary.Read(buf, binary.BigEndian, &rounds); err != nil {
			return nil, errors.New("cannot decode encrypted private keys: bad format")
		}

		var err error
		var password []byte
		if len(ctx.password) > 0 {
			password = ctx.password
		} else {
			password, err = ui.PromptPassword(fmt.Sprintf("Please enter the password to decrypt %s", ctx.filename))
			if err != nil {
				return nil, err
			}
		}

		// Derive the cipher key used in the cipher.
		k, err := bcrypt_pbkdf.Key(password, salt, int(rounds), sshDefaultKeyLength+aes.BlockSize)
		if err != nil {
			return nil, errors.Wrap(err, "error deriving password")
		}

		// Decrypt the private key using the derived secret.
		dst := make([]byte, len(w.PrivKeyBlock))
		iv := k[sshDefaultKeyLength : sshDefaultKeyLength+aes.BlockSize]
		block, err := aes.NewCipher(k[:sshDefaultKeyLength])
		if err != nil {
			return nil, errors.Wrap(err, "error creating cipher")
		}

		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(dst, w.PrivKeyBlock)
		w.PrivKeyBlock = dst
	}

	var pk1 openSSHPrivateKeyBlock
	if err := ssh.Unmarshal(w.PrivKeyBlock, &pk1); err != nil {
		if w.KdfName != "none" || w.CipherName != "none" {
			return nil, errors.New("incorrect passphrase supplied")
		}
		return nil, err
	}

	if pk1.Check1 != pk1.Check2 {
		if w.KdfName != "none" || w.CipherName != "none" {
			return nil, errors.New("incorrect passphrase supplied")
		}
		return nil, errors.New("error decoding key: check mismatch")
	}

	// we only handle ed25519 and rsa keys currently
	switch pk1.Keytype {
	case ssh.KeyAlgoRSA:
		// https://github.com/openssh/openssh-portable/blob/master/sshkey.c
		key := struct {
			N       *big.Int
			E       *big.Int
			D       *big.Int
			Iqmp    *big.Int
			P       *big.Int
			Q       *big.Int
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, err
		}

		for i, b := range key.Pad {
			if int(b) != i+1 {
				return nil, errors.New("error decoding key: padding not as expected")
			}
		}

		pk := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: key.N,
				E: int(key.E.Int64()),
			},
			D:      key.D,
			Primes: []*big.Int{key.P, key.Q},
		}

		if err := pk.Validate(); err != nil {
			return nil, err
		}

		pk.Precompute()

		return pk, nil
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		key := struct {
			Curve   string
			Pub     []byte
			D       *big.Int
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling key")
		}

		for i, b := range key.Pad {
			if int(b) != i+1 {
				return nil, errors.New("error decoding key: padding not as expected")
			}
		}

		var curve elliptic.Curve
		switch key.Curve {
		case "nistp256":
			curve = elliptic.P256()
		case "nistp384":
			curve = elliptic.P384()
		case "nistp521":
			curve = elliptic.P521()
		default:
			return nil, errors.Errorf("error decoding key: unsupported elliptic curve %s", key.Curve)
		}

		N := curve.Params().N
		X, Y := elliptic.Unmarshal(curve, key.Pub)
		if X == nil || Y == nil {
			return nil, errors.New("error decoding key: failed to unmarshal public key")
		}

		if key.D.Cmp(N) >= 0 {
			return nil, errors.New("error decoding key: scalar is out of range")
		}

		x, y := curve.ScalarBaseMult(key.D.Bytes())
		if x.Cmp(X) != 0 || y.Cmp(Y) != 0 {
			return nil, errors.New("error decoding key: public key does not match private key")
		}

		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     X,
				Y:     Y,
			},
			D: key.D,
		}, nil
	case ssh.KeyAlgoED25519:
		key := struct {
			Pub     []byte
			Priv    []byte
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, err
		}

		for i, b := range key.Pad {
			if int(b) != i+1 {
				return nil, errors.New("error decoding key: padding not as expected")
			}
		}

		if len(key.Priv) != ed25519.PrivateKeySize {
			return nil, errors.New("private key unexpected length")
		}

		pk := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
		copy(pk, key.Priv)
		return pk, nil
	default:
		return nil, errors.Errorf("unsupported key type %s", pk1.Keytype)
	}
}

// SerializeOpenSSHPrivateKey serialize a private key in the OpenSSH PEM format.
func SerializeOpenSSHPrivateKey(key crypto.PrivateKey, opts ...Options) (*pem.Block, error) {
	ctx := new(context)
	if err := ctx.apply(opts); err != nil {
		return nil, err
	}

	// Random check bytes.
	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, errors.Wrap(err, "error generating random check ")
	}

	w := openSSHPrivateKey{
		NumKeys: 1,
	}
	pk1 := openSSHPrivateKeyBlock{
		Check1: check,
		Check2: check,
	}

	var blockSize int
	if ctx.password == nil {
		w.CipherName = "none"
		w.KdfName = "none"
		blockSize = 8
	} else {
		w.CipherName = sshDefaultCiphername
		w.KdfName = sshDefaultKdf
		blockSize = aes.BlockSize
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		E := new(big.Int).SetInt64(int64(k.PublicKey.E))
		// Marshal public key:
		// E and N are in reversed order in the public and private key.
		pubKey := struct {
			KeyType string
			E       *big.Int
			N       *big.Int
		}{
			ssh.KeyAlgoRSA,
			E, k.PublicKey.N,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			N       *big.Int
			E       *big.Int
			D       *big.Int
			Iqmp    *big.Int
			P       *big.Int
			Q       *big.Int
			Comment string
		}{
			k.PublicKey.N, E,
			k.D, k.Precomputed.Qinv, k.Primes[0], k.Primes[1],
			ctx.comment,
		}
		pk1.Keytype = ssh.KeyAlgoRSA
		pk1.Rest = ssh.Marshal(key)
	case *ecdsa.PrivateKey:
		var curve, keyType string
		switch k.Curve.Params().Name {
		case "P-256":
			curve = "nistp256"
			keyType = ssh.KeyAlgoECDSA256
		case "P-384":
			curve = "nistp384"
			keyType = ssh.KeyAlgoECDSA384
		case "P-521":
			curve = "nistp521"
			keyType = ssh.KeyAlgoECDSA521
		default:
			return nil, errors.Errorf("error serializing key: unsupported curve %s", k.Curve.Params().Name)
		}

		pub := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Curve   string
			Pub     []byte
		}{
			keyType, curve, pub,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			Curve   string
			Pub     []byte
			D       *big.Int
			Comment string
		}{
			curve, pub, k.D,
			ctx.comment,
		}
		pk1.Keytype = keyType
		pk1.Rest = ssh.Marshal(key)
	case ed25519.PrivateKey:
		pub := make([]byte, ed25519.PublicKeySize)
		priv := make([]byte, ed25519.PrivateKeySize)
		copy(pub, k[ed25519.PublicKeySize:])
		copy(priv, k)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Pub     []byte
		}{
			ssh.KeyAlgoED25519, pub,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			Pub     []byte
			Priv    []byte
			Comment string
		}{
			pub, priv,
			ctx.comment,
		}
		pk1.Keytype = ssh.KeyAlgoED25519
		pk1.Rest = ssh.Marshal(key)
	default:
		return nil, errors.Errorf("unsupported key type %T", k)
	}

	w.PrivKeyBlock = ssh.Marshal(pk1)

	// Add padding until the private key block matches the block size,
	// 16 with AES encryption, 8 without.
	for i, l := 0, len(w.PrivKeyBlock); (l+i)%blockSize != 0; i++ {
		w.PrivKeyBlock = append(w.PrivKeyBlock, byte(i+1))
	}

	if ctx.password != nil {
		// Create encryption key derivation the password.
		salt, err := randutil.Salt(sshDefaultSaltLength)
		if err != nil {
			return nil, err
		}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint32(sshDefaultSaltLength))
		binary.Write(buf, binary.BigEndian, salt)
		binary.Write(buf, binary.BigEndian, uint32(sshDefaultRounds))
		w.KdfOpts = buf.String()

		// Derive key to encrypt the private key block.
		k, err := bcrypt_pbkdf.Key(ctx.password, salt, sshDefaultRounds, sshDefaultKeyLength+aes.BlockSize)
		if err != nil {
			return nil, errors.Wrap(err, "error deriving decryption key")
		}

		// Encrypt the private key using the derived secret.
		dst := make([]byte, len(w.PrivKeyBlock))
		iv := k[sshDefaultKeyLength : sshDefaultKeyLength+aes.BlockSize]
		block, err := aes.NewCipher(k[:sshDefaultKeyLength])
		if err != nil {
			return nil, errors.Wrap(err, "error creating cipher")
		}

		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(dst, w.PrivKeyBlock)
		w.PrivKeyBlock = dst
	}

	b := ssh.Marshal(w)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(sshMagic), b...),
	}

	if ctx.filename != "" {
		if err := utils.WriteFile(ctx.filename, pem.EncodeToMemory(block), ctx.perm); err != nil {
			return nil, errs.FileError(err, ctx.filename)
		}
	}

	return block, nil
}
