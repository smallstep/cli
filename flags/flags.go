package flags

import (
	"path/filepath"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

var (
	// KTY is the flag to set the key type.
	KTY = cli.StringFlag{
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
	Size = cli.IntFlag{
		Name: "size",
		Usage: `The <size> (in bits) of the key for RSA and oct key types. RSA keys require a
minimum key size of 2048 bits. If unset, default is 2048 bits for RSA keys and 128 bits for oct keys.`,
	}

	// Curve is the flag to se the key curve.
	Curve = cli.StringFlag{
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
	Subtle = cli.BoolFlag{
		Name: "subtle",
	}

	// Insecure is the flag required on insecure operations
	Insecure = cli.BoolFlag{
		Name: "insecure",
	}

	// Force is a cli.Flag used to overwrite files.
	Force = cli.BoolFlag{
		Name:  "f,force",
		Usage: "Force the overwrite of files without asking.",
	}

	// DryRun is a cli.Flag used to avoid the writing of files.
	DryRun = cli.BoolFlag{
		Name:  "dry-run",
		Usage: "Executes the command without changing any file.",
	}

	// PasswordFile is a cli.Flag used to pass a file to encrypt or decrypt a
	// private key.
	PasswordFile = cli.StringFlag{
		Name:  "password-file",
		Usage: `The path to the <file> containing the password to encrypt or decrypt the private key.`,
	}

	// NoPassword is a cli.Flag used to avoid using a password to encrypt private
	// keys.
	NoPassword = cli.BoolFlag{
		Name: "no-password",
		Usage: `Do not ask for a password to encrypt a private key. Sensitive key material will
be written to disk unencrypted. This is not recommended. Requires **--insecure** flag.`,
	}

	// Token is a cli.Flag used to pass the CA token.
	Token = cli.StringFlag{
		Name: "token",
		Usage: `The one-time <token> used to authenticate with the CA in order to create the
certificate.`,
	}

	// NotBefore is a cli.Flag used to pass the start period of the certificate
	// validity.
	NotBefore = cli.StringFlag{
		Name: "not-before",
		Usage: `The <time|duration> when the certificate validity period starts. If a <time> is
used it is expected to be in RFC 3339 format. If a <duration> is used, it is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h".`,
	}

	// NotAfter is a cli.Flag used to pass the end period of the certificate
	// validity.
	NotAfter = cli.StringFlag{
		Name: "not-after",
		Usage: `The <time|duration> when the certificate validity period ends. If a <time> is
used it is expected to be in RFC 3339 format. If a <duration> is used, it is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h".`,
	}

	// Provisioner is a cli.Flag used to pass the CA provisioner to use.
	Provisioner = cli.StringFlag{
		Name:  "provisioner,issuer",
		Usage: "The provisioner <name> to use.",
	}

	// CaURL is a cli.Flag used to pass the CA url.
	CaURL = cli.StringFlag{
		Name:  "ca-url",
		Usage: "<URI> of the targeted Step Certificate Authority.",
	}

	// Root is a cli.Flag used to pass the path of the root certificate to use.
	Root = cli.StringFlag{
		Name:  "root",
		Usage: "The path to the PEM <file> used as the root certificate authority.",
	}

	// Offline is a cli.Flag used to activate the offline flow.
	Offline = cli.BoolFlag{
		Name: "offline",
		Usage: `Creates a certificate without contacting the certificate authority. Offline mode
uses the configuration, certificates, and keys created with **step ca init**,
but can accept a different configuration file using '--ca-config>' flag.`,
	}

	// CaConfig is a cli.Flag used to pass the CA configuration file.
	CaConfig = cli.StringFlag{
		Name: "ca-config",
		Usage: `The <path> to the certificate authority configuration file. Defaults to
$STEPPATH/config/ca.json`,
		Value: filepath.Join(config.StepPath(), "config", "ca.json"),
	}

	// X5cCert is a cli.Flag used to pass the x5c header certificate for a JWT.
	X5cCert = cli.StringFlag{
		Name:  "x5c-cert",
		Usage: "Certificate (<chain>) in PEM format to store in the 'x5c' header of a JWT.",
	}

	// X5cKey is a cli.Flag used to pass the private key (corresponding to the x5c-cert)
	// that is used to sign the token.
	X5cKey = cli.StringFlag{
		Name: "x5c-key",
		Usage: `Private key <path>, used to sign a JWT, corresponding to the certificate that will
be stored in the 'x5c' header.`,
	}

	// SSHPOPCert is a cli.Flag used to pass the sshpop header certificate for a JWT.
	SSHPOPCert = cli.StringFlag{
		Name:  "sshpop-cert",
		Usage: "Certificate (<chain>) in PEM format to store in the 'sshpop' header of a JWT.",
	}

	// SSHPOPKey is a cli.Flag used to pass the private key (corresponding to the sshpop-cert)
	// that is used to sign the token.
	SSHPOPKey = cli.StringFlag{
		Name: "sshpop-key",
		Usage: `Private key <path>, used to sign a JWT, corresponding to the certificate that will
be stored in the 'sshpop' header.`,
	}
)

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

// ParseTimeDuration parses the not-before and not-after flags as a timeDuration
func ParseTimeDuration(ctx *cli.Context) (notBefore api.TimeDuration, notAfter api.TimeDuration, err error) {
	var zero api.TimeDuration
	notBefore, err = api.ParseTimeDuration(ctx.String("not-before"))
	if err != nil {
		return zero, zero, errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, err = api.ParseTimeDuration(ctx.String("not-after"))
	if err != nil {
		return zero, zero, errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	return
}
