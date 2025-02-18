package kdf

import (
	"crypto/subtle"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"

	"go.step.sm/crypto/randutil"

	"github.com/smallstep/cli/internal/cast"
)

// KDF is the type that all the key derivation functions implements. The
// current methods uses safe default values, but future improvements can add
// functional options to be able to use custom settings.
type KDF func(password []byte) (string, error)

// Scrypt uses scrypt-32768 to derive the given password. Returns the hash
// using the PHC string format.
func Scrypt(password []byte) (string, error) {
	salt, err := randutil.Salt(16)
	if err != nil {
		return "", err
	}

	// use scrypt-32768 by default
	p := scryptParams[scryptHash32768]
	hash, err := scrypt.Key(password, salt, p.N, p.r, p.p, p.kl)
	if err != nil {
		return "", errors.Wrap(err, "error deriving password")
	}

	return phcEncode("scrypt", p.getParams(), salt, hash), nil
}

// Bcrypt uses bcrypt to derive the given password. Returns the hash
// using the Modular Crypt Format standard for bcrypt implementations.
func Bcrypt(password []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "error deriving password")
	}
	return string(hash), nil
}

// Argon2i uses Argon2i variant to derive the given password. Returns the hash
// using the PHC string format.
//
// Argon2i is optimized to resist side-channel attacks.
func Argon2i(password []byte) (string, error) {
	salt, err := randutil.Salt(16)
	if err != nil {
		return "", err
	}

	p := argon2Params[argon2iHash]
	hash := argon2.Key(password, salt, p.t, p.m, p.p, p.kl)
	identifier := "argon2i$v=" + strconv.Itoa(argon2.Version)
	return phcEncode(identifier, p.getParams(), salt, hash), nil
}

// Argon2id uses Argon2id variant to derive the given password. Returns the
// hash using the PHC string format.
//
// Argon2id is an hybrid version of Argon2d, that maximizes resistance to GPU
// attacks and Argon2i that is optimized to resist side-channel attacks. The
// Internet draft (https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03)
// recommends using Argon2id.
func Argon2id(password []byte) (string, error) {
	salt, err := randutil.Salt(16)
	if err != nil {
		return "", err
	}

	p := argon2Params[argon2idHash]
	hash := argon2.IDKey(password, salt, p.t, p.m, p.p, p.kl)
	identifier := "argon2id$v=" + strconv.Itoa(argon2.Version)
	return phcEncode(identifier, p.getParams(), salt, hash), nil
}

// Compare compares the password with the given PHC encoded hash, returns true
// if they match. The time taken is a function of the length of the slices and
// is independent of the contents.
func Compare(password, phc []byte) (bool, error) {
	id, version, params, salt, hash, err := phcDecode(string(phc))
	if err != nil {
		return false, errors.Wrap(err, "error decoding hash")
	}

	var hashedPass []byte
	switch id {
	case bcryptHash:
		return (bcrypt.CompareHashAndPassword(hash, password) == nil), nil
	case scryptHash:
		p, err := newScryptParams(params)
		if err != nil {
			return false, err
		}
		hashedPass, err = scrypt.Key(password, salt, p.N, p.r, p.p, len(hash))
		if err != nil {
			return false, errors.Wrap(err, "error deriving input")
		}
	case argon2iHash:
		p, err := newArgon2Params(params)
		if err != nil {
			return false, err
		}
		if version != 0 && version != argon2.Version {
			return false, errors.Errorf("unsupported argon2 version '%d'", version)
		}
		hashedPass = argon2.Key(password, salt, p.t, p.m, p.p, cast.Uint32(len(hash)))
	case argon2idHash:
		p, err := newArgon2Params(params)
		if err != nil {
			return false, err
		}
		if version != 0 && version != argon2.Version {
			return false, errors.Errorf("unsupported argon2 version '%d'", version)
		}
		hashedPass = argon2.IDKey(password, salt, p.t, p.m, p.p, cast.Uint32(len(hash)))
	default:
		return false, errors.Errorf("invalid or unsupported hash method with id '%s'", id)
	}

	return (subtle.ConstantTimeCompare(hash, hashedPass) == 1), nil
}

// CompareString  compares the given password with the given PHC encoded hash,
// returns true if they match. The time taken is a function of the length of
// the slices and is independent of the contents.
func CompareString(password, phc string) (bool, error) {
	return Compare([]byte(password), []byte(phc))
}
