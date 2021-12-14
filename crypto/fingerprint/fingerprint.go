package fingerprint

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Encoding represents the fingerprint encoding type.
type Encoding int

const (
	// HexFingerprint represents the hex encoding of the fingerprint.
	HexFingerprint Encoding = iota
	// Base64StdFingerprint represents the base64 encoding of the fingerprint.
	Base64StdFingerprint
	// Base64URLFingerprint represents the base64URL encoding of the fingerprint.
	Base64URLFingerprint
	// Base64RawStdFingerprint represents the base64RawStd encoding of the fingerprint.
	Base64RawStdFingerprint
	// Base64RawURLFingerprint represents the base64RawURL encoding of the fingerprint.
	Base64RawURLFingerprint
	// EmojiFingerprint represents the emoji encoding of the fingerprint.
	EmojiFingerprint
)

type options struct {
	hash     crypto.Hash
	prefix   string
	encoding Encoding
}

func apply(opts []Option) options {
	o := options{
		encoding: HexFingerprint,
	}
	for _, f := range opts {
		f(&o)
	}
	return o
}

// Option customizes the fingerprint generation.
type Option func(*options)

// WithHash sets the hashing algorithm that is applied on the input before
// creating the fingerprint.
func WithHash(h crypto.Hash) Option {
	return func(o *options) {
		o.hash = h
	}
}

// WithPrefix sets a prefix that is prepended to the generated fingerprint.
func WithPrefix(prefix string) Option {
	return func(o *options) {
		o.prefix = prefix
	}
}

// WithEncoding sets the encoding that is used to generate the fingerprint.
func WithEncoding(enc Encoding) Option {
	return func(o *options) {
		o.encoding = enc
	}
}

// Fingerprint calculates the fingerprint of the input. By default, the
// fingerprint is encoded as a hex string without applying any hash algorithm.
// The behavior can be adjusted by providing the options.
func Fingerprint(input []byte, opts ...Option) string {
	o := apply(opts)

	// Compute hash if algorithm is configured.
	if o.hash != 0 {
		hash := o.hash.New()
		if _, err := hash.Write(input); err != nil {
			panic(fmt.Sprintf("BUG: hash must not return error: %s", err))
		}
		input = hash.Sum(nil)
	}

	return fmt.Sprintf("%s%s", o.prefix, encode(input, o.encoding))
}

func encode(input []byte, encoding Encoding) string {
	switch encoding {
	case HexFingerprint:
		return strings.ToLower(hex.EncodeToString(input))
	case Base64StdFingerprint:
		return base64.StdEncoding.EncodeToString(input)
	case Base64URLFingerprint:
		return base64.URLEncoding.EncodeToString(input)
	case Base64RawStdFingerprint:
		return base64.RawStdEncoding.EncodeToString(input)
	case Base64RawURLFingerprint:
		return base64.RawURLEncoding.EncodeToString(input)
	case EmojiFingerprint:
		return toEmoji(input)
	default:
		panic(fmt.Sprintf("BUG: invalid encoding: %#v", encoding))
	}
}

// Decode decods a fingerprint to the raw bytes.
func Decode(input string, opts ...Option) ([]byte, error) {
	o := apply(opts)
	input = strings.TrimPrefix(input, o.prefix)
	return decode(input, o.encoding)
}

func decode(input string, encoding Encoding) ([]byte, error) {
	switch encoding {
	case HexFingerprint:
		return hex.DecodeString(input)
	case Base64StdFingerprint:
		return base64.StdEncoding.DecodeString(input)
	case Base64URLFingerprint:
		return base64.URLEncoding.DecodeString(input)
	case Base64RawStdFingerprint:
		return base64.RawStdEncoding.DecodeString(input)
	case Base64RawURLFingerprint:
		return base64.RawURLEncoding.DecodeString(input)
	case EmojiFingerprint:
		return nil, errors.New("decoding emoji fingerprint not supported")
	default:
		panic(fmt.Sprintf("BUG: invalid encoding: %#v", encoding))
	}
}
