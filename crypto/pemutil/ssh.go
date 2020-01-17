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
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/pkg/bcrypt_pbkdf"
	"github.com/smallstep/cli/ui"
	"golang.org/x/crypto/ssh"
)

const (
	sshDefaultKdf        = "bcrypt"
	sshDefaultCiphername = "aes256-ctr"
	sshDefaultKeyLength  = 32
	sshDefaultSaltLength = 16
	sshDefaultRounds     = 16
)

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

	const magic = "openssh-key-v1\x00"
	if len(key) < len(magic) || string(key[:len(magic)]) != magic {
		return nil, errors.New("invalid openssh private key format")
	}
	remaining := key[len(magic):]

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

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

		// Decrypt the crypt using the derived secret.
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

	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}{}

	if err := ssh.Unmarshal(w.PrivKeyBlock, &pk1); err != nil {
		return nil, err
	}

	if pk1.Check1 != pk1.Check2 {
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
			Priv    []byte
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling key")
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
			return nil, errors.New("error decoding key: failed to unmarshal curve")
		}

		D := new(big.Int).SetBytes(key.Priv)
		if D.Cmp(N) >= 0 {
			return nil, errors.New("error decoding key: scalar is out of range")
		}

		x, y := curve.ScalarBaseMult(key.Priv)
		if x.Cmp(X) != 0 || y.Cmp(Y) != 0 {
			return nil, errors.New("error decoding key: public key does not match")
		}

		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     X,
				Y:     Y,
			},
			D: D,
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

		if len(key.Priv) != ed25519.PrivateKeySize {
			return nil, errors.New("private key unexpected length")
		}

		for i, b := range key.Pad {
			if int(b) != i+1 {
				return nil, errors.New("padding not as expected")
			}
		}

		pk := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
		copy(pk, key.Priv)
		return pk, nil
	default:
		return nil, errors.New("unhandled key type")
	}
}
