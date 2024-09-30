package ssh

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/ca/identity"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
)

func certificateCommand() cli.Command {
	return cli.Command{
		Name:   "certificate",
		Action: command.ActionFunc(certificateAction),
		Usage:  "sign a SSH certificate using the SSH CA",
		UsageText: `**step ssh certificate** <key-id> <key-file>
[**--host**] [--**host-id**] [**--sign**] [**--principal**=<string>]
[**--password-file**=<file>] [**--provisioner-password-file**=<file>]
[**--add-user**] [**--not-before**=<time|duration>] [**--comment**=<comment>]
[**--not-after**=<time|duration>] [**--token**=<token>] [**--issuer**=<name>]
[**--console**] [**--no-password**] [**--insecure**] [**--force**] [**--x5c-cert**=<file>]
[**--x5c-key**=<file>] [**--k8ssa-token-path**=<file>] [**--no-agent**]
[**--kty**=<key-type>] [**--curve**=<curve>] [**--size**=<size>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,

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

Generate a new SSH key pair and user certificate and do not add to SSH agent:
'''
$ step ssh certificate mariano@work id_ecdsa --no-agent
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

Sign an SSH public key and generate a host certificate with a custom uuid:
'''
$ step ssh certificate --host --host-id 00000000-0000-0000-0000-000000000000 \
	--sign internal.example.com ssh_host_ecdsa_key.pub
'''

Sign an SSH public key and generate a host certificate with a uuid derived
from '/etc/machine-id':
'''
$ step ssh certificate --host --host-id machine --sign \
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
'''

Create an EC pair with curve P-521 and certificate:

'''
$  step ssh certificate --kty EC --curve "P-521" mariano@work id_ecdsa
'''

Create an Octet Key Pair with curve Ed25519 and certificate:

'''
$  step ssh certificate --kty OKP --curve Ed25519 mariano@work id_ed25519
'''`,

		Flags: []cli.Flag{
			flags.Force,
			flags.Insecure,
			flags.NoPassword,
			flags.NotBefore,
			flags.NotAfter,
			flags.Offline,
			flags.Provisioner,
			flags.Token,
			flags.TemplateSet,
			flags.TemplateSetFile,
			flags.Console,
			sshAddUserFlag,
			sshHostFlag,
			sshHostIDFlag,
			sshPasswordFileFlag,
			sshPrincipalFlag,
			sshPrivateKeyFlag,
			sshProvisionerPasswordFlag,
			sshSignFlag,
			flags.KTY,
			flags.Curve,
			flags.Size,
			flags.Comment,
			flags.KMSUri,
			flags.X5cCert,
			flags.X5cKey,
			flags.X5cChain,
			flags.NebulaCert,
			flags.NebulaKey,
			flags.K8sSATokenPathFlag,
			cli.BoolFlag{
				Name:  "no-agent",
				Usage: "Do not add the generated certificate and associated private key to the SSH agent.",
			},
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
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

	comment := ctx.String("comment")
	if comment == "" {
		comment = subject
	}

	// Flags
	token := ctx.String("token")
	isHost := ctx.Bool("host")
	hostID := ctx.String("host-id")
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
	templateData, err := flags.ParseTemplateData(ctx)
	if err != nil {
		return err
	}

	kty, curve, size, err := utils.GetKeyDetailsFromCLI(ctx, insecure, "kty", "curve", "size")
	if err != nil {
		return err
	}

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
	case !isHost && hostID != "":
		return errs.RequiredWithFlag(ctx, sshHostIDFlag.Name, sshHostFlag.Name)
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
			principals = createPrincipalsFromSubject(subject)
		}
	}

	var (
		sshPub      ssh.PublicKey
		pub, priv   interface{}
		flowOptions []cautils.Option
	)

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
		if sshPrivKeyFile != "" {
			if priv, err = pemutil.Read(sshPrivKeyFile); err != nil {
				return errors.Wrap(err, "error parsing private key")
			}
		}
		flowOptions = append(flowOptions, cautils.WithSSHPublicKey(sshPub))
	} else {
		// Generate keypair
		pub, priv, err = keyutil.GenerateKeyPair(kty, curve, size)
		if err != nil {
			return err
		}

		sshPub, err = ssh.NewPublicKey(pub)
		if err != nil {
			return errors.Wrap(err, "error creating public key")
		}
	}

	flow, err := cautils.NewCertificateFlow(ctx, flowOptions...)
	if err != nil {
		return err
	}
	if token == "" {
		if token, err = flow.GenerateSSHToken(ctx, subject, tokType, principals, validAfter, validBefore); err != nil {
			return err
		}
	}

	caClient, err := flow.GetClient(ctx, token)
	if err != nil {
		return err
	}

	version, err := caClient.Version()
	if err != nil {
		return err
	}

	// Generate identity certificate (x509) if necessary
	var identityCSR api.CertificateRequest
	var identityKey crypto.PrivateKey
	if version.RequireClientAuthentication {
		csr, key, err := ca.CreateIdentityRequest(subject)
		if err != nil {
			return err
		}

		// All host identity certs need a URI SAN to work with our ssh API.
		if isHost {
			var u uuid.UUID
			switch hostID {
			case "":
				// If there is an old identity cert lying around, by default use the host ID so that running
				// this command twice doesn't clobber your old host ID.
				u, err = readExistingUUID()
				if err != nil {
					u, err = uuid.NewRandom()
					if err != nil {
						return errs.Wrap(err, "Unable to generate a host-id.")
					}
				}
			case "machine":
				u, err = deriveMachineID()
				if err != nil {
					return errs.Wrap(err, "Unable to derive a host-id. Make sure /etc/machine-id exists.")
				}
			default:
				u, err = uuid.Parse(hostID)
				if err != nil {
					return errs.InvalidFlagValue(ctx, sshHostIDFlag.Name, hostID, "[ machine | <UUID> ]")
				}
			}
			uri, err := url.Parse(u.URN())
			if err != nil {
				return errs.Wrap(err, "failed parsing uuid urn")
			}

			template := &x509.CertificateRequest{
				Subject:        csr.Subject,
				DNSNames:       csr.DNSNames,
				IPAddresses:    csr.IPAddresses,
				EmailAddresses: csr.EmailAddresses,
				// Prepend the generated uri. There is code that expects the
				// uuid URI to be the first one.
				URIs: append([]*url.URL{uri}, csr.URIs...),
			}
			csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
			if err != nil {
				return errs.Wrap(err, "failed creating certificate request")
			}
			newCSR, err := x509.ParseCertificateRequest(csrBytes)
			if err != nil {
				return errs.Wrap(err, "failed parsing certificate request bytes")
			}
			if err := newCSR.CheckSignature(); err != nil {
				return errs.Wrap(err, "failed signature check on new csr")
			}
			csr.CertificateRequest = newCSR
		}

		identityCSR = *csr
		identityKey = key
	}

	var sshAuPub ssh.PublicKey
	var sshAuPubBytes []byte
	var auPub, auPriv interface{}
	if isAddUser {
		auPub, auPriv, err = keyutil.GenerateKeyPair(kty, curve, size)
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
		KeyID:            subject,
		ValidAfter:       validAfter,
		ValidBefore:      validBefore,
		AddUserPublicKey: sshAuPubBytes,
		IdentityCSR:      identityCSR,
		TemplateData:     templateData,
	})
	if err != nil {
		return err
	}

	// Write files
	if !isSign {
		// Private key (with password unless --no-password --insecure)
		opts := []pemutil.Options{
			pemutil.WithOpenSSH(true),
			pemutil.ToFile(keyFile, 0600),
		}
		switch {
		case noPassword && insecure:
		case passwordFile != "":
			opts = append(opts, pemutil.WithPasswordFile(passwordFile))
		default:
			opts = append(opts, pemutil.WithPasswordPrompt("Please enter the password to encrypt the private key", func(s string) ([]byte, error) {
				return ui.PromptPassword(s, ui.WithValidateNotEmpty())
			}))
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
	if isAddUser && resp.AddUserCertificate != nil {
		id := provisioner.SanitizeSSHUserPrincipal(subject) + "-provisioner"
		if _, err := pemutil.Serialize(auPriv, pemutil.WithOpenSSH(true), pemutil.ToFile(baseName+"-provisioner", 0600)); err != nil {
			return err
		}
		if err := utils.WriteFile(baseName+"-provisioner.pub", marshalPublicKey(sshAuPub, id), 0644); err != nil {
			return err
		}
		if err := utils.WriteFile(baseName+"-provisioner-cert.pub", marshalPublicKey(resp.AddUserCertificate, id), 0644); err != nil {
			return err
		}
	}

	// Write x509 identity certificate
	if version.RequireClientAuthentication {
		if err := ca.WriteDefaultIdentity(resp.IdentityCertificate, identityKey); err != nil {
			return err
		}
	}

	if !isSign {
		ui.PrintSelected("Private Key", keyFile)
		ui.PrintSelected("Public Key", pubFile)
	}
	ui.PrintSelected("Certificate", crtFile)

	// Attempt to add key to agent if private key defined.
	if !ctx.Bool("no-agent") && priv != nil && certType == provisioner.SSHUserCert {
		if agent, err := sshutil.DialAgent(); err != nil {
			ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
		} else {
			defer agent.Close()
			if err := agent.AddCertificate(comment, resp.Certificate.Certificate, priv); err != nil {
				ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
			} else {
				ui.PrintSelected("SSH Agent", "yes")
			}
		}
	}

	if isAddUser && resp.AddUserCertificate != nil {
		ui.PrintSelected("Add User Private Key", baseName+"-provisioner")
		ui.PrintSelected("Add User Public Key", baseName+"-provisioner.pub")
		ui.PrintSelected("Add User Certificate", baseName+"-provisioner-cert.pub")
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

func deriveMachineID() (uuid.UUID, error) {
	// use /etc/machine-id
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return uuid.Nil, err
	}

	// 16 bytes, not secret
	key := []byte("man moon machine")
	mac, err := blake2b.New(16, key)
	if err != nil {
		return uuid.Nil, err
	}
	mac.Write(machineID)
	machineHash := mac.Sum(nil)
	var u uuid.UUID
	copy(u[:], machineHash)
	// Make it a v4 uuid (taken from uuid.NewRandom):
	u[6] = (u[6] & 0x0f) | 0x40 // Version 4
	u[8] = (u[8] & 0x3f) | 0x80 // Variant is 10

	return u, nil
}

func readExistingUUID() (uuid.UUID, error) {
	id, err := identity.LoadDefaultIdentity()
	if err != nil {
		return uuid.Nil, errs.Wrap(err, "error loading default identity")
	}
	if err := id.Validate(); err != nil {
		return uuid.Nil, errs.Wrap(err, "error validating identity file")
	}
	certs, err := pemutil.ReadCertificateBundle(id.Certificate)
	if err != nil {
		return uuid.Nil, errs.Wrap(err, "error parsing default identity")
	}
	leaf := certs[0]
	if len(leaf.URIs) < 1 {
		return uuid.Nil, errors.New("incompatible certificate: missing host uuid")
	}
	uri := leaf.URIs[0]
	// TODO: add a smallstep namespace at some point
	//       so we can actually find our host id
	u, err := uuid.Parse(uri.String())
	if err != nil {
		return uuid.Nil, errs.Wrap(err, "error parsing host-id")
	}
	return u, nil
}
