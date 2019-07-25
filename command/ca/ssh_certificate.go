package ca

import (
	"bytes"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

var (
	sshPrincipalFlag = cli.StringSliceFlag{
		Name: "principal,n",
		Usage: `Add the principals (users or hosts) that the token is authorized to
		request. The signing request using this token won't be able to add
		extra names. Use the '--principal' flag multiple times to configure
		multiple ones. The '--principal' flag and the '--token' flag are
		mutually exlusive.`,
	}

	sshHostFlag = cli.BoolFlag{
		Name:  "host",
		Usage: `Create a host certificate instead of a user certificate.`,
	}

	sshSignFlag = cli.BoolFlag{
		Name:  "sign",
		Usage: `Sign the public key passed as an argument instead of creating one.`,
	}
)

func sshCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "ssh-certificate",
		Action: command.ActionFunc(sshCertificateAction),
		Usage:  "sign a SSH certificate using the the SSH CA",
		UsageText: `**step ca ssh-certificate** <key-id> <key-file>
		[**--host**] [**--sign]`,
		Description: `**step ca ssh-certificate** command generates an SSH key pair and creates a
certificate using [step certificates](https://github.com/smallstep/certificates).

With a certificate clients or servers may trust only the CA key and verify its
signature on a certificate rather than trusting many user/host keys.

Note that not all the provisioner types will be able to generate user and host
certificates. Currently JWK provisioners can generate both, but with an OIDC
provisioner you will only be able to generate user certificates unless you are
and admin that can generate both. With a cloud identity provisioner you will
only be able to generate host certificates.

To configure a server to accept user certificates and provide a user certificate
you need to add the following lines in </etc/ssh/sshd_config>:
'''
# The path to the CA public key, it accepts multiple CAs, one per line
TrustedUserCAKeys /etc/ssh/ca.pub

# Path to the private key and certificate
HostKey /etc/ssh/ssh_host_ecdsa_key
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
'''

And to configure a client to accept host certificates you need to add the CA in
<~/.ssh/known_hosts> with the following format:
'''
@cert-authority *.example.com ecdsa-sha2-nistp256 AAAAE...=
'''

Where <*.example.com> is a pattern that matches the hosts and
<ecdsa-sha2-nistp256 AAAAE...=> should be the contents of the CA public key.

## POSITIONAL ARGUMENTS

<key-id>
:  The certificate identity. If no principals are passed we will use
the key-id as a principal, if it has the format abc@def then the principal will
be abc.

<key-file>
:  The private key name when generating a new key pair, or the public
key path when we are just signing it.

## EXAMPLES

Generate a new SSH key pair and user certificate:
'''
$ step ca ssh-certificate mariano@work id_ecdsa
'''

Sign an SSH public key and generate a user certificate:
'''
$ step ca ssh-certificate --sign mariano@work id_ecdsa.pub
'''

Generate a new SSH key pair and host certificate:
'''
$ step ca ssh-certificate --host internal.example.com ssh_host_ecdsa_key
'''

Sign an SSH public key and generate a host certificate:
'''
$ step ca ssh-certificate --host --sign \
	internal.example.com ssh_host_ecdsa_key.pub
'''

Generate a new key pair, and a certificate with custom principals (user/host names):
'''
$ step ca ssh-certificate --principal max --principal mariano --sign \
	ops@work id_ecdsa
'''

Sign an SSH public key generating a certificate with given token:
'''
$ step ca ssh-certificate --token $TOKEN mariano@work id_ecdsa
'''`,
		Flags: []cli.Flag{
			tokenFlag,
			sshPrincipalFlag,
			sshHostFlag,
			sshSignFlag,
			notBeforeCertFlag,
			notAfterCertFlag,
			provisionerIssuerFlag,
			caURLFlag,
			rootFlag,
			offlineFlag,
			caConfigFlag,
			flags.Force,
		},
	}
}

func sshCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	subject := args.Get(0)
	keyFile := args.Get(1)
	// SSH uses fixed suffixes for public keys and certificates
	pubFile := keyFile + ".pub"
	crtFile := keyFile + "-cert.pub"

	// Flags
	token := ctx.String("token")
	isHost := ctx.Bool("host")
	isSign := ctx.Bool("sign")
	principals := ctx.StringSlice("principal")
	validAfter, validBefore, err := parseTimeDuration(ctx)
	if err != nil {
		return err
	}

	// If we are signing a public key, get the proper name for the certificate
	if isSign && strings.HasSuffix(keyFile, ".pub") {
		crtFile = keyFile[:len(keyFile)-4] + "-cert.pub"
	}

	// By default use the first part of the subject as a principal
	if len(principals) == 0 {
		principals = append(principals, sanitizeUsername(subject))
	}

	flow, err := newCertificateFlow(ctx)
	if err != nil {
		return err
	}

	var certType string
	if isHost {
		certType = provisioner.SSHHostCert
	} else {
		certType = provisioner.SSHUserCert
	}

	if len(token) == 0 {
		if token, err = flow.GenerateSSHToken(ctx, subject, certType, principals); err != nil {
			return err
		}
	}

	caClient, err := flow.getClient(ctx, subject, token)
	if err != nil {
		return err
	}

	var sshPub ssh.PublicKey
	var pub, priv interface{}

	if isSign {
		// Used given public key
		in, err := utils.ReadFile(keyFile)
		if err != nil {
			return err
		}

		sshPub, _, _, _, err = ssh.ParseAuthorizedKey(in)
		if err != nil {
			return errors.Wrap(err, "error parsing public key")
		}
	} else {
		// Generate keypair
		pub, priv, err = keys.GenerateDefaultKeyPair()
		if err != nil {
			return err
		}

		sshPub, err = ssh.NewPublicKey(pub)
		if err != nil {
			return errors.Wrap(err, "error creating public key")
		}
	}

	resp, err := caClient.SignSSH(&api.SignSSHRequest{
		PublicKey:   sshPub.Marshal(),
		OTT:         token,
		Principals:  principals,
		CertType:    certType,
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
	})
	if err != nil {
		return err
	}

	// Write files
	if !isSign {
		if err := utils.WriteFile(pubFile, marshalPublicKey(sshPub, subject), 0644); err != nil {
			return err
		}
		ui.PrintSelected("Public Key", pubFile)

		_, err = pemutil.Serialize(priv, pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return err
		}
		ui.PrintSelected("Private Key", keyFile)
	}

	if err := utils.WriteFile(crtFile, marshalPublicKey(resp.Certificate, subject), 0644); err != nil {
		return err
	}
	ui.PrintSelected("Certificate", crtFile)

	return nil
}

func sanitizeUsername(s string) string {
	if i := strings.Index(s, "@"); i >= 0 {
		return strings.ToLower(s[:i])
	}
	return s
}

func marshalPublicKey(key ssh.PublicKey, subject string) []byte {
	b := ssh.MarshalAuthorizedKey(key)
	if i := bytes.LastIndex(b, []byte("\n")); i >= 0 {
		return append(b[:i], []byte(" "+subject+"\n")...)
	}
	return append(b, []byte(" "+subject+"\n")...)
}
