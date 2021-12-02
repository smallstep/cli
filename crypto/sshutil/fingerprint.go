package sshutil

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/fingerprint"
	"golang.org/x/crypto/ssh"
)

type fingerprintOptions struct {
	FingerprintOptions []fingerprint.Option
}

func apply(opts []FingerprintOption) fingerprintOptions {
	var o fingerprintOptions
	for _, f := range opts {
		f(&o)
	}
	return o
}

// FingerprintOption customizes the fingerprint generation.
type FingerprintOption func(*fingerprintOptions)

// WithFingerprintOptions sets the fingerprint options.
func WithFingerprintOptions(opts ...fingerprint.Option) FingerprintOption {
	return func(o *fingerprintOptions) {
		if len(opts) != 0 {
			o.FingerprintOptions = opts
		} else {
			o.FingerprintOptions = nil
		}
	}
}

// Fingerprint returns the key size, fingerprint, comment and algorithm of a
// public key.
func Fingerprint(in []byte, opts ...FingerprintOption) (string, error) {
	o := apply(opts)

	key, comment, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		return "", errors.Wrap(err, "error parsing public key")
	}
	if comment == "" {
		comment = "no comment"
	}

	typ, size, err := publicKeyTypeAndSize(key)
	if err != nil {
		return "", errors.Wrap(err, "error determining key type and size")
	}

	fp := ssh.FingerprintSHA256(key)
	if len(o.FingerprintOptions) != 0 {
		raw, err := fingerprint.Decode(fp, fingerprint.WithPrefix("SHA256:"), fingerprint.WithEncoding(fingerprint.Base64RawStdFingerprint))
		if err != nil {
			return "", errors.Wrap(err, "decoding fingerprint")
		}
		fp = fingerprint.Fingerprint(raw, o.FingerprintOptions...)
	}

	return fmt.Sprintf("%d %s %s (%s)", size, fp, comment, typ), nil
}
