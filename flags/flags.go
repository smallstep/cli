package flags

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/step"
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

	// K8sSATokenPathFlag is an optional flag that allows modification of the
	// kubernetes service account token path.
	K8sSATokenPathFlag = cli.StringFlag{
		Name:  "k8ssa-token-path",
		Usage: `Configure the <file> from which to read the kubernetes service account token.`,
		Value: `/var/run/secrets/kubernetes.io/serviceaccount/token`,
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

	// AdminProvisioner is a cli.Flag used to pass the CA Admin provisioner to use.
	AdminProvisioner = cli.StringFlag{
		Name:  "admin-provisioner,admin-issuer",
		Usage: "The provisioner <name> to use for generating admin credentials.",
	}

	// AdminSubject is a cli.Flag used to pass the admin subject to use when generating
	// admin credentials.
	AdminSubject = cli.StringFlag{
		Name:  "admin-subject,admin-name",
		Usage: "The admin <subject> to use for generating admin credentials.",
	}

	// ProvisionerPasswordFile is a cli.Flag used to pass the password file to
	// decrypt the generating key.
	ProvisionerPasswordFile = cli.StringFlag{
		Name: "provisioner-password-file",
		Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
	}

	// ProvisionerPasswordFileWithAlias is a cli.Flag that allows multiple
	// alias flag names for the ProvisionerPasswordFile.
	ProvisionerPasswordFileWithAlias = cli.StringFlag{
		Name: "provisioner-password-file,password-file",
		Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
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

	// Context is a cli.Flag used to pass the context to for the given command.
	Context = cli.StringFlag{
		Name:  "context",
		Usage: "The <context> to apply before running the given command.",
	}

	// Offline is a cli.Flag used to activate the offline flow.
	Offline = cli.BoolFlag{
		Name: "offline",
		Usage: `Creates a certificate without contacting the certificate authority. Offline mode
uses the configuration, certificates, and keys created with **step ca init**,
but can accept a different configuration file using **--ca-config** flag.`,
	}

	// CaConfig is a cli.Flag used to pass the CA configuration file.
	CaConfig = cli.StringFlag{
		Name: "ca-config",
		Usage: `The certificate authority configuration <file>. Defaults to
$STEPPATH/config/ca.json`,
		Value: filepath.Join(step.Path(), "config", "ca.json"),
	}

	// AdminCert is a cli.Flag used to pass the x5c header certificate for a JWT.
	AdminCert = cli.StringFlag{
		Name:  "admin-cert",
		Usage: "Admin certificate (<chain>) in PEM format to store in the 'x5c' header of a JWT.",
	}

	// AdminKey is a cli.Flag used to pass the private key (corresponding to the x5c-cert)
	// that is used to sign the token.
	AdminKey = cli.StringFlag{
		Name: "admin-key",
		Usage: `Private key <file>, used to sign a JWT, corresponding to the admin certificate that will
be stored in the 'x5c' header.`,
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
		Usage: `Private key <file>, used to sign a JWT, corresponding to the certificate that will
be stored in the 'x5c' header.`,
	}

	// X5tCert is a cli.Flag used to pass the x5t header certificate thumbprint
	// for a JWS or JWT.
	X5tCert = cli.StringFlag{
		Name:  "x5t-cert",
		Usage: "Certificate <file> in PEM format to use for the 'x5t' header of a JWS or JWT",
	}

	// X5tKey is a cli.Flag used to pass the private key (corresponding to the x5t-cert)
	// that is used to sign the token.
	X5tKey = cli.StringFlag{
		Name: "x5t-key",
		Usage: `Private key <file>, used to sign a JWT, corresponding to the certificate used for
the 'x5t' header.`,
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
		Usage: `Private key <file>, used to sign a JWT, corresponding to the certificate that will
be stored in the 'sshpop' header.`,
	}

	// Team is a cli.Flag used to pass the team ID.
	Team = cli.StringFlag{
		Name:  "team",
		Usage: "The team <ID> used to bootstrap the environment.",
	}

	// TeamURL is a cli.Flag used to pass the team URL.
	TeamURL = cli.StringFlag{
		Name: "team-url",
		Usage: `The <url> step queries to retrieve initial team configuration. Only used with
the **--team** option. If the url contains <\<\>> placeholders, they are replaced with the team ID.`,
	}

	// RedirectURL is a cli.Flag used to pass a url to redirect after an OAuth
	// flow finishes..
	RedirectURL = cli.StringFlag{
		Name:  "redirect-url",
		Usage: "The <url> to open in the system browser when the OAuth flow is successful.",
	}

	// ServerName is a cli.Flag used to set the TLS Server Name Indication in
	// request to a server.
	ServerName = cli.StringFlag{
		Name:  "servername",
		Usage: `TLS Server Name Indication that should be sent to request a specific certificate from the server.`,
	}

	// TemplateSet is a cli.Flag used to send key-value pairs to the ca.
	TemplateSet = cli.StringSliceFlag{
		Name:  "set",
		Usage: "The <key=value> pair with template data variables to send to the CA. Use the **--set** flag multiple times to add multiple variables.",
	}

	// TemplateSetFile is a cli.Flag used to send a JSON file to the CA.
	TemplateSetFile = cli.StringFlag{
		Name:  "set-file",
		Usage: "The JSON <file> with the template data to send to the CA.",
	}

	// Identity is a cli.Flag used to be able to define the identity argument in
	// defaults.json.
	Identity = cli.StringFlag{
		Name: "identity",
		Usage: `The certificate identity. It is usually passed as a positional argument, but a
flag exists so it can be configured in $STEPPATH/config/defaults.json.`,
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
func ParseTimeDuration(ctx *cli.Context) (notBefore, notAfter api.TimeDuration, err error) {
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

// ParseTemplateData parses the set and and set-file flags and returns a json
// message to be used in certificate templates.
func ParseTemplateData(ctx *cli.Context) (json.RawMessage, error) {
	data := make(map[string]interface{})
	if path := ctx.String("set-file"); path != "" {
		b, err := utils.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &data); err != nil {
			return nil, errors.Wrapf(err, "error unmarshaling %s", path)
		}
	}

	keyValues := ctx.StringSlice("set")
	for _, s := range keyValues {
		i := strings.Index(s, "=")
		if i == -1 {
			return nil, errs.InvalidFlagValue(ctx, "set", s, "")
		}
		key, value := s[:i], s[i+1:]

		// If the value is not json, use the raw string.
		var v interface{}
		if err := json.Unmarshal([]byte(value), &v); err == nil {
			data[key] = v
		} else {
			data[key] = value
		}
	}

	if len(data) == 0 {
		return nil, nil
	}

	return json.Marshal(data)
}

// ParseCaURL gets and parses the ca-url from the command context.
//  - Require non-empty value.
//  - Prepend an 'https' scheme if the URL does not have a scheme.
//  - Error if the URL scheme is not implicitly or explicitly 'https'.
func ParseCaURL(ctx *cli.Context) (string, error) {
	caURL := ctx.String("ca-url")
	if caURL == "" {
		return "", errs.RequiredFlag(ctx, "ca-url")
	}

	return parseCaURL(ctx, caURL)
}

// ParseCaURLIfExists gets and parses the ca-url from the command context, if
// one is present.
//  - Allow empty value.
//  - Prepend an 'https' scheme if the URL does not have a scheme.
//  - Error if the URL scheme is not implicitly or explicitly 'https'.
func ParseCaURLIfExists(ctx *cli.Context) (string, error) {
	caURL := ctx.String("ca-url")
	if caURL == "" {
		return "", nil
	}
	return parseCaURL(ctx, caURL)
}

func parseCaURL(ctx *cli.Context, caURL string) (string, error) {
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}
	u, err := url.Parse(caURL)
	if err != nil {
		return "", errs.InvalidFlagValueMsg(ctx, "ca-url", caURL, "invalid URL")
	}
	if u.Scheme != "https" {
		return "", errs.InvalidFlagValueMsg(ctx, "ca-url", caURL, "must have https scheme")
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}
