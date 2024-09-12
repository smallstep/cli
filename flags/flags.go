package flags

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/step"
	"go.step.sm/crypto/fingerprint"

	"github.com/smallstep/cli/utils"
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
		Name:  "subtle",
		Usage: "Allow delicate operations.",
	}

	// SubtleHidden is the hidden flag required for delicate operations.
	SubtleHidden = cli.BoolFlag{
		Name:   "subtle",
		Hidden: true,
	}

	// Insecure is the flag required on insecure operations
	Insecure = cli.BoolFlag{
		Name: "insecure",
	}

	// InsecureHidden is the hidden flag required on insecure operations.
	InsecureHidden = cli.BoolFlag{
		Name:   "insecure",
		Hidden: true,
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

	// Limit is a cli.Flag used to limit the number of entities returned in API requests.
	Limit = cli.UintFlag{
		Name:  "limit",
		Usage: `The number of entities to return per (paging) API request.`,
	}

	// NoPager is a cli.Flag used to disable usage of $PAGER for paging purposes.
	NoPager = cli.BoolFlag{
		Name:  "no-pager",
		Usage: `Disables usage of $PAGER for paging purposes`,
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

	// CertNotBefore is a cli.Flag used to pass the start period of the certificate
	// validity. This is currently only used for SSH certificates.
	CertNotBefore = cli.StringFlag{
		Name: "cert-not-before",
		Usage: `The <time|duration> when the certificate validity period starts. If a <time> is
used it is expected to be in RFC 3339 format. If a <duration> is used, it is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h". This flag is only supported on SSH certificates.`,
	}

	// CertNotAfter is a cli.Flag used to pass the end period of the certificate
	// validity. This is currently only used for SSH certificates.
	CertNotAfter = cli.StringFlag{
		Name: "cert-not-after",
		Usage: `The <time|duration> when the certificate validity period ends. If a <time> is
used it is expected to be in RFC 3339 format. If a <duration> is used, it is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h". This flag is only supported on SSH certificates.`,
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

	// AdminPasswordFileWithAlias is a cli.Flag used to pass the password to use
	// when generating admin credentials.
	AdminPasswordFile = cli.StringFlag{
		Name: "admin-password-file,password-file",
		Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
	}

	// AdminPasswordFileNoAlias is a cli.Flag used to pass the password to use
	// when generating admin credentials.
	AdminPasswordFileNoAlias = cli.StringFlag{
		Name: "admin-password-file",
		Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
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

	// HiddenNoContext is a cli.Flag that prevents context configuration
	// from being applied for a given command.
	HiddenNoContext = cli.BoolTFlag{
		Name:   "no-context",
		Usage:  "Do not apply context specific environment for this command.",
		Hidden: true,
	}

	// Context is a cli.Flag used to select a a context name.
	Context = cli.StringFlag{
		Name:  "context",
		Usage: "The context <name> to apply for the given command.",
	}

	// ContextProfile is a cli.Flag to select a context profile name.
	ContextProfile = cli.StringFlag{
		Name:  "profile",
		Usage: `The <name> that will serve as the profile name for the context.`,
	}

	// ContextAuthority is a cli.Flag used to select a context authority name.
	ContextAuthority = cli.StringFlag{
		Name:  "authority",
		Usage: `The <name> that will serve as the authority name for the context.`,
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
$(step path)/config/ca.json`,
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

	// X5cChain is a cli.Flag used to pass the intermediate chain certificates corresponding to the x5c-cert
	// that is used to sign the token.
	X5cChain = cli.StringSliceFlag{
		Name:  "x5c-chain",
		Usage: `Certificate <file>, in PEM format`,
	}

	// X5cInsecure is a cli.Flag used to set the JWT header x5cInsecure instead
	// of x5c when --x5c-cert is used.
	X5cInsecure = cli.BoolFlag{
		Name:  "x5c-insecure",
		Usage: "Use the JWT header 'x5cInsecure' instead of 'x5c'.",
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

	// NebulaCert is a cli.Flag used to pass the nebula certificate used as the
	// nebula header certificate in a JWT.
	NebulaCert = cli.StringFlag{
		Name:  "nebula-cert",
		Usage: "Certificate <file> in PEM format to store in the 'nebula' header of a JWT.",
	}

	// NebulaKey is a cli.Flag used to pass the private key (corresponding to
	// the nebula-cert) that is used to sign the token.
	NebulaKey = cli.StringFlag{
		Name: "nebula-key",
		Usage: `Private key <file>, used to sign a JWT, corresponding to the certificate that will
be stored in the 'nebula' header.`,
	}

	// Confirmation is a cli.Flag used to add a confirmation claim in the token.
	Confirmation = cli.StringFlag{
		Name:  "cnf",
		Usage: `The <fingerprint> of the CSR to restrict this token for.`,
	}

	// ConfirmationFile is a cli.Flag used to add a confirmation claim in the
	// tokens. It will add a confirmation kid with the fingerprint of the CSR.
	ConfirmationFile = cli.StringFlag{
		Name:  "cnf-file",
		Usage: `The CSR <file> to restrict this token for.`,
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
the **--team** option. If the url contains <\<\>> placeholders, they are replaced with the team ID.
Replacing the authority-id section of the url is not supported with placeholders.`,
	}

	// TeamAuthority is a cli.Flag used to pass the name of the authority belonging
	// to a team.
	TeamAuthority = cli.StringFlag{
		Name: "team-authority",
		Usage: `The <sub-domain> of the certificate authority to bootstrap. E.g., for an authority with
domain name 'certs.example-team.ca.smallstep.com' the value would be 'certs'.`,
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

	// Template is a cli.Flag used to set the template file to use.
	Template = cli.StringFlag{
		Name:  "template",
		Usage: `The certificate template <file>, a JSON representation of the certificate to create.`,
	}

	// TemplateSet is a cli.Flag used to send key-value pairs to the ca.
	TemplateSet = cli.StringSliceFlag{
		Name:  "set",
		Usage: "The <key=value> pair with template data variables. Use the **--set** flag multiple times to add multiple variables.",
	}

	// TemplateSetFile is a cli.Flag used to send a JSON file to the CA.
	TemplateSetFile = cli.StringFlag{
		Name:  "set-file",
		Usage: "The JSON <file> with the template data variables.",
	}

	// Identity is a cli.Flag used to be able to define the identity argument in
	// defaults.json.
	Identity = cli.StringFlag{
		Name: "identity",
		Usage: `The certificate identity. It is usually passed as a positional argument, but a
flag exists so it can be configured in $STEPPATH/config/defaults.json.`,
	}

	// EABKeyID is a cli.Flag that points to an ACME EAB Key ID
	EABKeyID = cli.StringFlag{
		Name:  "eab-key-id",
		Usage: "An ACME EAB Key ID.",
	}

	// EABReference is a cli.Flag that points to an ACME EAB Key Reference
	EABReference = cli.StringFlag{
		Name:  "eab-key-reference",
		Usage: "An ACME EAB Key Reference.",
	}

	KMSUri = cli.StringFlag{
		Name:  "kms",
		Usage: "The <uri> to configure a Cloud KMS or an HSM.",
	}

	AttestationURI = cli.StringFlag{
		Name:  "attestation-uri",
		Usage: "The KMS <uri> used for attestation.",
	}

	Comment = cli.StringFlag{
		Name:  "comment",
		Usage: "The comment used when adding the certificate to an agent. Defaults to the subject if not provided.",
	}

	Console = cli.BoolFlag{
		Name:  "console",
		Usage: `Complete the flow while remaining inside the terminal.`,
	}
)

// FingerprintFormatFlag returns a flag for configuring the fingerprint format.
func FingerprintFormatFlag(defaultFmt string) cli.StringFlag {
	return cli.StringFlag{
		Name:  "format",
		Usage: `The <format> of the fingerprint, it must be "hex", "base64", "base64-url", "base64-raw", "base64-url-raw" or "emoji".`,
		Value: defaultFmt,
	}
}

// FingerprintCertificateModeFlag returns a flag for configuring the fingerprinting
// mode. The default behavior is to fingerprint just the public key if an SSH certificate
// is being fingerprinted. By providing `--certificate`, the certificate bytes will
// be included in calculating the fingerprint, resulting in a different one.
func FingerprintCertificateModeFlag() cli.BoolFlag {
	return cli.BoolFlag{
		Name:  "certificate",
		Usage: `Include SSH certificate bytes in fingerprint`,
	}
}

// ParseFingerprintFormat gets the fingerprint encoding from the format flag.
func ParseFingerprintFormat(format string) (fingerprint.Encoding, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "hex":
		return fingerprint.HexFingerprint, nil
	case "base64":
		return fingerprint.Base64Fingerprint, nil
	case "base64url", "base64-url":
		return fingerprint.Base64URLFingerprint, nil
	case "base64urlraw", "base64url-raw", "base64-url-raw":
		return fingerprint.Base64RawURLFingerprint, nil
	case "base64raw", "base64-raw":
		return fingerprint.Base64RawFingerprint, nil
	case "emoji", "emojisum":
		return fingerprint.EmojiFingerprint, nil
	default:
		return 0, errors.Errorf("error parsing fingerprint format: '%s' is not a valid fingerprint format", format)
	}
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

// ParseTemplateData parses the set and set-file flags and returns a json
// message to be used in certificate templates.
func ParseTemplateData(ctx *cli.Context) (json.RawMessage, error) {
	data, err := GetTemplateData(ctx)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return json.Marshal(data)
}

// GetTemplateData parses the set and set-file flags and returns a map to be
// used in certificate templates.
func GetTemplateData(ctx *cli.Context) (map[string]interface{}, error) {
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

	return data, nil
}

// ParseCaURL gets and parses the ca-url from the command context.
//   - Require non-empty value.
//   - Prepend an 'https' scheme if the URL does not have a scheme.
//   - Error if the URL scheme is not implicitly or explicitly 'https'.
func ParseCaURL(ctx *cli.Context) (string, error) {
	caURL := ctx.String("ca-url")
	if caURL == "" && !ctx.Bool("offline") {
		return "", errs.RequiredFlag(ctx, "ca-url")
	}

	return parseCaURL(ctx, caURL)
}

// ParseCaURLIfExists gets and parses the ca-url from the command context, if
// one is present.
//   - Allow empty value.
//   - Prepend an 'https' scheme if the URL does not have a scheme.
//   - Error if the URL scheme is not implicitly or explicitly 'https'.
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

	hostname := u.Hostname()
	host := hostname
	if u.Port() != "" {
		host += ":" + u.Port()
	}
	_, _, err = net.SplitHostPort(host)
	// if host represents a valid IPv6 address, ensure that it contains brackets
	if err != nil && strings.Contains(err.Error(), "too many colons in address") {
		// this is most probably an IPv6 without brackets, e.g. ::1, 2001:0db8:85a3:0000:0000:8a2e:0370:7334
		// in case a port was appended to this wrong format, we try to extract the port, then check if it's
		// still a valid IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334:8443 (8443 is the port). If none of
		// these cases, then the input dns is not changed.
		lastIndex := strings.LastIndex(host, ":")
		hostPart, portPart := host[:lastIndex], host[lastIndex+1:]
		if ip := net.ParseIP(hostPart); ip != nil {
			hostname = "[" + hostPart + "]:" + portPart
		} else if ip := net.ParseIP(host); ip != nil {
			hostname = "[" + host + "]"
		}
		u.Host = hostname
	}

	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}
