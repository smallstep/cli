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
