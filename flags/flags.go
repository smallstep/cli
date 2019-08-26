package flags

import (
	"time"

	"github.com/urfave/cli"
)

// KTY is the flag to set the key type.
var KTY = cli.StringFlag{
	Name:  "kty",
	Value: "EC",
	Usage: `The <kty> to build the certificate upon.
If unset, default is EC.

: <kty> is a case-sensitive string and must be one of:

    **EC**
    :  Create an **elliptic curve** keypair

    **OKP**
    :  Create an octet key pair (for **"Ed25519"** curve)

    **RSA**
    :  Create an **RSA** keypair`,
}

// Size is the flag to set the key size.
var Size = cli.IntFlag{
	Name: "size",
	Usage: `The <size> (in bits) of the key for RSA and oct key types. RSA keys require a
minimum key size of 2048 bits. If unset, default is 2048 bits for RSA keys and 128 bits for oct keys.`,
}

// Curve is the flag to se the key curve.
var Curve = cli.StringFlag{
	Name: "crv, curve",
	Usage: `The elliptic <curve> to use for EC and OKP key types. Corresponds
to the **"crv"** JWK parameter. Valid curves are defined in JWA [RFC7518]. If
unset, default is P-256 for EC keys and Ed25519 for OKP keys.

: <curve> is a case-sensitive string and must be one of:

		**P-256**
		:  NIST P-256 Curve

		**P-384**
		:  NIST P-384 Curve

		**P-521**
		:  NIST P-521 Curve

		**Ed25519**
		:  Ed25519 Curve`,
}

// Subtle is the flag required for delicate operations.
var Subtle = cli.BoolFlag{
	Name: "subtle",
}

// Insecure is the flag required on insecure operations
var Insecure = cli.BoolFlag{
	Name: "insecure",
}

// Force is a cli.Flag used to overwrite files.
var Force = cli.BoolFlag{
	Name:  "f,force",
	Usage: "Force the overwrite of files without asking.",
}

// PasswordFile is a cli.Flag used to pass a file to encrypt or decrypt a
// private key.
var PasswordFile = cli.StringFlag{
	Name:  "password-file",
	Usage: `The path to the <file> containing the password to encrypt or decrypt the private key.`,
}

// NoPassword is a cli.Flag used to avoid using a password to encrypt private
// keys.
var NoPassword = cli.BoolFlag{
	Name: "no-password",
	Usage: `Do not ask for a password to encrypt a private key. Sensitive key material will
be written to disk unencrypted. This is not recommended. Requires **--insecure** flag.`,
}

// ParseTimeOrDuration is a helper that returns the time or the current time
// with an extra duration. It's used in flags like --not-before, --not-after.
func ParseTimeOrDuration(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, true
	}

	var t time.Time
	if err := t.UnmarshalText([]byte(s)); err != nil {
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, false
		}
		t = time.Now().Add(d)
	}
	return t, true
}
