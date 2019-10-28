package ssh

import (
	"bytes"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func certificateCommand() cli.Command {
	return cli.Command{
		Name:   "certificate",
		Action: command.ActionFunc(certificateAction),
		Usage:  "sign a SSH certificate using the the SSH CA",
		UsageText: `**step ssh certificate** <key-id> <key-file>
[**--host**] [**--sign**] [**--principal**=<string>] [**--password-file**=<path>]
[**--provisioner-password-file**=<path>] [**--add-user**]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--token**=<token>] [**--issuer**=<name>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--no-password**] [**--insecure**] [**--force**]`,
		Description: `**step ssh certificate** command generates an SSH key pair and creates a
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
# The path to the CA public key, it accepts multiple user CAs, one per line
TrustedUserCAKeys /etc/ssh/ssh_user_key.pub

# Path to the private key and certificate
HostKey /etc/ssh/ssh_host_ecdsa_key
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
'''

Make sure to restart the sshd daemon to refresh its configuration.

To configure clients to accept host certificates you need to add the host CA public
key in <~/.ssh/known_hosts> with the following format:
'''
@cert-authority *.example.com ecdsa-sha2-nistp256 AAAAE...=
'''

Where <*.example.com> is a pattern that matches the hosts and
<ecdsa-sha2-nistp256 AAAAE...=> should be the contents of the host CA public key.

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
$ step ssh certificate mariano@work id_ecdsa
'''

Generate a new SSH key pair and user certificate and set the lifetime to 2hrs:
'''
$ step ssh certificate mariano@work id_ecdsa --not-after 2h
'''

Generate a new SSH key pair and user certificate and set the lifetime to begin
2hrs from now and last for 8hrs:
'''
$ step ssh certificate mariano@work id_ecdsa --not-before 2h --not-after 10h
'''

Sign an SSH public key and generate a user certificate:
'''
$ step ssh certificate --sign mariano@work id_ecdsa.pub
'''

Generate a new SSH key pair and host certificate:
'''
$ step ssh certificate --host internal.example.com ssh_host_ecdsa_key
'''

Sign an SSH public key and generate a host certificate:
'''
$ step ssh certificate --host --sign \
	internal.example.com ssh_host_ecdsa_key.pub
'''

Generate an ssh certificate with custom principals from an existing key pair and
add the certificate to the ssh agent:
'''
$ step ssh certificate --principal max --principal mariano --sign \
	ops@work id_ecdsa.pub --private-key id_ecdsa_key
'''

Generate a new key pair and a certificate using a given token:
'''
$ step ssh certificate --token $TOKEN mariano@work id_ecdsa
'''`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Force,
			flags.Insecure,
			flags.Root,
			flags.NoPassword,
			flags.NotBefore,
			flags.NotAfter,
			flags.Offline,
			flags.Provisioner,
			flags.Token,
			sshAddUserFlag,
			sshHostFlag,
			sshPasswordFileFlag,
			sshPrincipalFlag,
			sshPrivateKeyFlag,
			sshProvisionerPasswordFlag,
			sshSignFlag,
		},
	}
}

func certificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	subject := args.Get(0)
	keyFile := args.Get(1)
	baseName := keyFile
	// SSH uses fixed suffixes for public keys and certificates
	pubFile := baseName + ".pub"
	crtFile := baseName + "-cert.pub"

	// Flags
	token := ctx.String("token")
	isHost := ctx.Bool("host")
	isSign := ctx.Bool("sign")
	isAddUser := ctx.Bool("add-user")
	principals := ctx.StringSlice("principal")
	passwordFile := ctx.String("password-file")
	provisionerPasswordFile := ctx.String("provisioner-password-file")
	noPassword := ctx.Bool("no-password")
	insecure := ctx.Bool("insecure")
	sshPrivKeyFile := ctx.String("private-key")
	validAfter, validBefore, err := flags.ParseTimeDuration(ctx)
	if err != nil {
		return err
	}

	// Hack to make the flag "password-file" the content of
	// "provisioner-password-file" so the token command works as expected
	ctx.Set("password-file", provisionerPasswordFile)

	// Validation
	switch {
	case noPassword && !insecure:
		return errs.RequiredInsecureFlag(ctx, "no-password")
	case noPassword && passwordFile != "":
		return errs.IncompatibleFlagWithFlag(ctx, "no-password", "password-file")
	case token != "" && provisionerPasswordFile != "":
		return errs.IncompatibleFlagWithFlag(ctx, "token", "provisioner-password-file")
	case isHost && isAddUser:
		return errs.IncompatibleFlagWithFlag(ctx, "host", "add-user")
	case isAddUser && len(principals) > 1:
		return errors.New("flag '--add-user' is incompatible with more than one principal")
	}

	// If we are signing a public key, get the proper name for the certificate
	if isSign && strings.HasSuffix(keyFile, ".pub") {
		baseName = keyFile[:len(keyFile)-4]
		crtFile = baseName + "-cert.pub"
	}

	var (
		certType string
		tokType  int
	)

	if isHost {
		certType = provisioner.SSHHostCert
		tokType = cautils.SSHHostSignType
	} else {
		certType = provisioner.SSHUserCert
		tokType = cautils.SSHUserSignType
	}

	// By default use the first part of the subject as a principal
	if len(principals) == 0 {
		if isHost {
			principals = append(principals, subject)
		} else {
			principals = append(principals, provisioner.SanitizeSSHUserPrincipal(subject))
		}
	}

	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}
	if len(token) == 0 {
		if token, err = flow.GenerateSSHToken(ctx, subject, tokType, principals, validAfter, validBefore); err != nil {
			return err
		}
	}

	caClient, err := flow.GetClient(ctx, token)
	if err != nil {
		return err
	}

	var sshPub ssh.PublicKey
	var pub, priv interface{}

	if isSign {
		// Use public key supplied as input.
		in, err := utils.ReadFile(keyFile)
		if err != nil {
			return err
		}

		sshPub, _, _, _, err = ssh.ParseAuthorizedKey(in)
		if err != nil {
			return errors.Wrap(err, "error parsing ssh public key")
		}
		if len(sshPrivKeyFile) > 0 {
			if priv, err = pemutil.Read(sshPrivKeyFile); err != nil {
				return errors.Wrap(err, "error parsing private key")
			}
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

	var sshAuPub ssh.PublicKey
	var sshAuPubBytes []byte
	var auPub, auPriv interface{}
	if isAddUser {
		auPub, auPriv, err = keys.GenerateDefaultKeyPair()
		if err != nil {
			return err
		}
		sshAuPub, err = ssh.NewPublicKey(auPub)
		if err != nil {
			return errors.Wrap(err, "error creating public key")
		}
		sshAuPubBytes = sshAuPub.Marshal()
	}

	resp, err := caClient.SSHSign(&api.SSHSignRequest{
		PublicKey:        sshPub.Marshal(),
		OTT:              token,
		Principals:       principals,
		CertType:         certType,
		ValidAfter:       validAfter,
		ValidBefore:      validBefore,
		AddUserPublicKey: sshAuPubBytes,
	})
	if err != nil {
		return err
	}

	// Write files
	if !isSign {
		// Private key (with password unless --no-password --insecure)
		opts := []pemutil.Options{
			pemutil.ToFile(keyFile, 0600),
		}
		switch {
		case noPassword && insecure:
		case passwordFile != "":
			opts = append(opts, pemutil.WithPasswordFile(passwordFile))
		default:
			opts = append(opts, pemutil.WithPasswordPrompt("Please enter the password to encrypt the private key"))
		}
		_, err = pemutil.Serialize(priv, opts...)
		if err != nil {
			return err
		}

		if err := utils.WriteFile(pubFile, marshalPublicKey(sshPub, subject), 0644); err != nil {
			return err
		}
	}

	// Write certificate
	if err := utils.WriteFile(crtFile, marshalPublicKey(resp.Certificate, subject), 0644); err != nil {
		return err
	}

	// Write Add User keys and certs
	if isAddUser {
		id := provisioner.SanitizeSSHUserPrincipal(subject) + "-provisioner"
		if _, err := pemutil.Serialize(auPriv, pemutil.ToFile(baseName+"-provisioner", 0600)); err != nil {
			return err
		}
		if err := utils.WriteFile(baseName+"-provisioner.pub", marshalPublicKey(sshAuPub, id), 0644); err != nil {
			return err
		}
		if err := utils.WriteFile(baseName+"-provisioner-cert.pub", marshalPublicKey(resp.AddUserCertificate, id), 0644); err != nil {
			return err
		}
	}

	if !isSign {
		ui.PrintSelected("Private Key", keyFile)
		ui.PrintSelected("Public Key", pubFile)
	}
	ui.PrintSelected("Certificate", crtFile)

	// Attempt to add key to agent if private key defined.
	if priv != nil {
		if agent, err := sshutil.DialAgent(); err != nil {
			ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
		} else {
			defer agent.Close()
			if err := agent.AddCertificate(subject, resp.Certificate.Certificate, priv); err != nil {
				ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
			} else {
				ui.PrintSelected("SSH Agent", "yes")
			}
		}
	}

	if isAddUser {
		ui.PrintSelected("Provisioner Private Key", baseName+"-provisioner")
		ui.PrintSelected("Provisioner Public Key", baseName+"-provisioner.pub")
		ui.PrintSelected("Provisioner Certificate", baseName+"-provisioner-cert.pub")
	}

	return nil
}

func marshalPublicKey(key ssh.PublicKey, subject string) []byte {
	b := ssh.MarshalAuthorizedKey(key)
	if i := bytes.LastIndex(b, []byte("\n")); i >= 0 {
		return append(b[:i], []byte(" "+subject+"\n")...)
	}
	return append(b, []byte(" "+subject+"\n")...)
}
