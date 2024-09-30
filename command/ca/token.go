package ca

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
)

func tokenCommand() cli.Command {
	return cli.Command{
		Name:   "token",
		Action: command.ActionFunc(tokenAction),
		Usage:  "generate an OTT granting access to the CA",
		UsageText: `**step ca token** <subject>
[--**kid**=<kid>] [--**issuer**=<name>]
[**--cert-not-before**=<time|duration>] [**--cert-not-after**=<time|duration>]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--password-file**=<file>] [**--provisioner-password-file**=<file>]
[**--output-file**=<file>] [**--kms**=uri] [**--key**=<file>] [**--san**=<SAN>] [**--offline**]
[**--revoke**] [**--x5c-cert**=<file>] [**--x5c-key**=<file>] [**--x5c-insecure**]
[**--sshpop-cert**=<file>] [**--sshpop-key**=<file>]
[**--cnf**=<fingerprint>] [**--cnf-file**=<file>]
[**--ssh**] [**--host**] [**--principal**=<name>] [**--k8ssa-token-path**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Description: `**step ca token** command generates a one-time token granting access to the
certificates authority.

## POSITIONAL ARGUMENTS

<subject>
:  The Common Name, DNS Name, or IP address that will be set by the certificate authority.
When there are no additional Subject Alternative Names configured (via the
--san flag), the subject will be added as the only element of the 'sans' claim
on the token.

## EXAMPLES

 Most of the following examples assumes that **--ca-url** and **--root** are
 set using environment variables or the default configuration file in
 <$STEPPATH/config/defaults.json>.

Get a new token for a DNS. Because there are no Subject Alternative Names
configured (via the '--san' flag), the 'sans' claim of the token will have a
default value of ['internal.example.com']:
'''
$ step ca token internal.example.com
'''

Get a new token for a 'Revoke' request:
'''
$ step ca token --revoke 146103349666685108195655980390445292315
'''

Get a new token for an IP address. Because there are no Subject Alternative Names
configured (via the '--san' flag), the 'sans' claim of the token will have a
default value of ['192.168.10.10']:
'''
$ step ca token 192.168.10.10
'''

Get a new token with custom Subject Alternative Names. The value of the 'sans'
claim of the token will be ['1.1.1.1', 'hello.example.com'] - 'foobar' will not
be in the 'sans' claim unless explicitly configured via the '--san' flag:
'''
$ step ca token foobar --san 1.1.1.1 --san hello.example.com
'''

Get a new token that expires in 30 minutes:
'''
$ step ca token --not-after 30m internal.example.com
'''

Get a new token that becomes valid in 30 minutes and expires 5 minutes after that:
'''
$ step ca token --not-before 30m --not-after 35m internal.example.com
'''

Get a new token with a confirmation claim to enforce a given CSR fingerprint:
'''
$ step certificate fingerprint --format base64-url-raw internal.csr
PJLNhtQoBE1yGN_ZKzr4Y2U5pyqIGiyyszkoz2raDOw
$ step ca token --cnf PJLNhtQoBE1yGN_ZKzr4Y2U5pyqIGiyyszkoz2raDOw internal.smallstep.com
'''

Get a new token with a confirmation claim to enforce the use of a given CSR:
'''
step ca token --cnf-file internal.csr internal.smallstep.com
'''

Get a new token signed with the given private key, the public key must be
configured in the certificate authority:
'''
$ step ca token internal.smallstep.com --key token.key
'''

Get a new token for a specific provisioner kid, ca-url and root:
'''
$ step ca token internal.example.com \
    --kid 4vn46fbZT68Uxfs9LBwHkTvrjEvxQqx-W8nnE-qDjts \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt
'''

Get a new token using the simple offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca token internal.example.com --offline
'''

Get a new token using the offline mode with all the parameters:
'''
$ step ca token internal.example.com \
    --offline \
    --kid 4vn46fbZT68Uxfs9LBwHkTvrjEvxQqx-W8nnE-qDjts \
    --issuer you@example.com \
    --key provisioner.key \
    --ca-url https://ca.example.com \
    --root /path/to/root_ca.crt
'''

Get a new token for a 'Revoke' request:
'''
$ step ca token --revoke 146103349666685108195655980390445292315
'''

Get a new token in offline mode for a 'Revoke' request:
'''
$ step ca token --offline --revoke 146103349666685108195655980390445292315
'''

Get a new token for an SSH user certificate:
'''
$ step ca token max@smallstep.com --ssh
'''

Get a new token for an SSH host certificate:
'''
$ step ca token my-remote.hostname --ssh --host
'''

Get a new token with a confirmation claim to enforce the use of a given public key:
'''
step ca token --ssh --host --cnf-file internal.pub internal.smallstep.com
'''

Generate a renew token and use it in a renew after expiry request:
'''
$ TOKEN=$(step ca token --x5c-cert internal.crt --x5c-key internal.key --renew internal.example.com)
$ curl -X POST -H "Authorization: Bearer $TOKEN" https://ca.example.com/1.0/renew
'''

Generate a JWK provisioner token using a key in a YubiKey:
'''
$ step ca token --kms yubikey:pin-value=123456 --key yubikey:slot-id=82 internal.example.com
'''

Generate an X5C provisioner token using a certificate in a YubiKey. Note that a
YubiKey does not support storing a certificate bundle. To make it work, you must
add the intermediate and the root in the provisioner configuration:
'''
$ step ca token --kms yubikey:pin-value=123456 \
  --x5c-cert yubikey:slot-id=82 --x5c-key yubikey:slot-id=82 \
  internal.example.com
'''`,
		Flags: []cli.Flag{
			provisionerKidFlag,
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add <dns|ip|email|uri> Subject Alternative Name(s) (SANs)
that should be authorized. A certificate signing request using this token must
match the complete set of SANs in the token 1:1. Use the '--san' flag multiple
times to configure multiple SANs.`,
			},
			cli.StringSliceFlag{
				Name: "principal,n",
				Usage: `Add the principals (user or host <name>s) that the token is authorized to
request. The signing request using this token won't be able to add
extra names. Use the '--principal' flag multiple times to configure
multiple principals.`,
			},
			sshHostFlag,
			flags.CaConfig,
			flags.Force,
			flags.NotAfter,
			flags.NotBefore,
			flags.CertNotAfter,
			flags.CertNotBefore,
			flags.Provisioner,
			flags.PasswordFile,
			flags.ProvisionerPasswordFile,
			flags.KMSUri,
			flags.X5cCert,
			flags.X5cKey,
			flags.X5cInsecure,
			flags.SSHPOPCert,
			flags.SSHPOPKey,
			flags.NebulaCert,
			flags.NebulaKey,
			flags.Confirmation,
			flags.ConfirmationFile,
			cli.StringFlag{
				Name: "key",
				Usage: `The private key <file> used to sign the JWT. This is usually downloaded from
the certificate authority.`,
			},
			cli.StringFlag{
				Name:  "output-file",
				Usage: "The destination <file> of the generated one-time token.",
			},
			cli.BoolFlag{
				Name: "revoke",
				Usage: `Create a token for authorizing 'Revoke' requests. The audience will
be invalid for any other API request.`,
			},
			cli.BoolFlag{
				Name: "renew",
				Usage: `Create a token for authorizing 'renew' requests. The audience will
be invalid for any other API request.`,
			},
			cli.BoolFlag{
				Name: "rekey",
				Usage: `Create a token for authorizing 'rekey' requests. The audience will
be invalid for any other API request.`,
			},
			cli.BoolFlag{
				Name:  "ssh",
				Usage: `Create a token for authorizing an SSH certificate signing request.`,
			},
			flags.K8sSATokenPathFlag,
			flags.Offline,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func tokenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	subject := ctx.Args().Get(0)
	outputFile := ctx.String("output-file")
	offline := ctx.Bool("offline")
	// x.509 flags
	sans := ctx.StringSlice("san")
	isRevoke := ctx.Bool("revoke")
	isRenew := ctx.Bool("renew")
	isRekey := ctx.Bool("rekey")
	// ssh flags
	isSSH := ctx.Bool("ssh")
	isHost := ctx.Bool("host")
	principals := ctx.StringSlice("principal")
	// confirmation claims
	cnfFile := ctx.String("cnf-file")
	cnf := ctx.String("cnf")

	switch {
	case isSSH && len(sans) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "ssh", "san")
	case isHost && len(sans) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "host", "san")
	case len(principals) > 0 && len(sans) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "principal", "san")
	case !isSSH && isHost:
		return errs.RequiredWithFlag(ctx, "host", "ssh")
	case !isSSH && len(principals) > 0:
		return errs.RequiredWithFlag(ctx, "principal", "ssh")
	case cnfFile != "" && cnf != "":
		return errs.IncompatibleFlagWithFlag(ctx, "cnf-file", "cnf")
	}

	// Default token type is always a 'Sign' token.
	var typ int
	if isSSH {
		switch {
		case isRevoke:
			typ = cautils.SSHRevokeType
		case isRenew:
			typ = cautils.SSHRenewType
		case isRekey:
			typ = cautils.SSHRekeyType
		case isHost:
			typ = cautils.SSHHostSignType
			sans = principals
		default:
			typ = cautils.SSHUserSignType
			sans = principals
		}
	} else {
		switch {
		case isRevoke:
			typ = cautils.RevokeType
		case isRenew:
			typ = cautils.RenewType
		default:
			typ = cautils.SignType
		}
	}

	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
	}

	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	// Add options to create a confirmation claim if a CSR or SSH public key is
	// passed.
	var tokenOpts []cautils.Option
	if cnfFile != "" {
		in, err := utils.ReadFile(cnfFile)
		if err != nil {
			return err
		}
		if isSSH {
			sshPub, _, _, _, err := ssh.ParseAuthorizedKey(in)
			if err != nil {
				return errors.Wrap(err, "error parsing ssh public key")
			}
			tokenOpts = append(tokenOpts, cautils.WithSSHPublicKey(sshPub))
		} else {
			csr, err := pemutil.ParseCertificateRequest(in)
			if err != nil {
				return errors.Wrap(err, "error parsing certificate request")
			}
			tokenOpts = append(tokenOpts, cautils.WithCertificateRequest(csr))
		}
	} else if cnf != "" {
		tokenOpts = append(tokenOpts, cautils.WithConfirmationFingerprint(cnf))
	}

	// --san and --type revoke are incompatible. Revocation tokens do not support SANs.
	if typ == cautils.RevokeType && len(sans) > 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "san", "revoke")
	}

	// parse times or durations
	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}

	// parse certificates durations
	certNotBefore, err := api.ParseTimeDuration(ctx.String("cert-not-before"))
	if err != nil {
		return errs.InvalidFlagValue(ctx, "cert-not-before", ctx.String("cert-not-before"), "")
	}
	certNotAfter, err := api.ParseTimeDuration(ctx.String("cert-not-after"))
	if err != nil {
		return errs.InvalidFlagValue(ctx, "cert-not-after", ctx.String("cert-not-after"), "")
	}

	var token string
	if offline {
		token, err = cautils.OfflineTokenFlow(ctx, typ, subject, sans, notBefore, notAfter, certNotBefore, certNotAfter)
		if err != nil {
			return err
		}
	} else {
		token, err = cautils.NewTokenFlow(ctx, typ, subject, sans, caURL, root, notBefore, notAfter, certNotBefore, certNotAfter, tokenOpts...)
		if err != nil {
			return err
		}
	}
	if outputFile != "" {
		return utils.WriteFile(outputFile, []byte(token), 0600)
	}
	fmt.Println(token)
	return nil
}
