package utils

// WritePublicKey encodes a crypto public key to a file on disk in PEM format.
import (
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/errs"
)

// WritePublicKey encodes a crypto public key to a file on disk in PEM format.
// Any file with the same name will be overwritten.
func WritePublicKey(key interface{}, out string) error {
	// Remove any file with same name, if it exists.
	if _, err := os.Stat(out); err == nil {
		if err = os.Remove(out); err != nil {
			return errs.FileError(err, out)
		}
	}
	keyOut, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		os.FileMode(0600))
	if err != nil {
		return errs.FileError(err, out)
	}
	pubPEM, err := keys.PublicPEM(key)
	if err != nil {
		return errs.Wrap(err,
			"failed to convert public key to PEM block")
	}
	err = pem.Encode(keyOut, pubPEM)
	if err != nil {
		return errs.Wrap(err,
			"pem encode '%s' failed", out)
	}
	keyOut.Close()
	return nil
}

// WritePrivateKey encodes a crypto private key to a file on disk in PEM format.
// Any file with the same name will be overwritten.
func WritePrivateKey(key interface{}, pass, out string) error {
	// Remove any file with same name, if it exists.
	// Permissions on private key files may be such that overwriting them is impossible.
	if _, err := os.Stat(out); err == nil {
		if err = os.Remove(out); err != nil {
			return errs.FileError(err, out)
		}
	}
	keyOut, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		os.FileMode(0600))
	if err != nil {
		return errs.FileError(err, out)
	}
	privPem, err := keys.PrivatePEM(key, keys.DefaultEncOpts(pass))
	if err != nil {
		return errors.Wrap(err,
			"failed to convert private key to PEM block")
	}
	err = pem.Encode(keyOut, privPem)
	if err != nil {
		return errors.Wrapf(err,
			"pem encode '%s' failed", out)
	}
	keyOut.Close()
	return nil
}
