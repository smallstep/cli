package ssh

import (
	"os"
	"strconv"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca/identity"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
)

func rekeyCommand() cli.Command {
	return cli.Command{
		Name:   "rekey",
		Action: command.ActionFunc(rekeyAction),
		Usage:  "rekey a SSH certificate using the SSH CA",
		UsageText: `**step ssh rekey** <ssh-cert> <ssh-key> [**--out**=<file>]
[**--issuer**=<name>] [**--password-file**=<file>] [**--force**]
[**--offline**] [**--ca-config**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step ssh rekey** command generates a new SSH Certificate and key using
an existing SSH Certificate and key pair to authenticate and templatize the
request. It writes the new certificate to disk - either overwriting
<ssh-cert> or using new files when the **--out**=<file> flag is used.

## POSITIONAL ARGUMENTS

<ssh-cert>
:  The ssh certificate to renew.

<ssh-key>
:  The ssh certificate private key.

## EXAMPLES

Rekey an ssh certificate:
'''
$ step ssh rekey id_ecdsa-cert.pub id_ecdsa
'''

Rekey an ssh certificate creating id2_ecdsa, id2_ecdsa.pub, and id2_ecdsa-cert.pub:
'''
$ step ssh rekey --out id2_ecdsa id_ecdsa-cert.pub id_ecdsa
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out",
				Usage: `The new key <file>. Defaults to overwriting the <ssh-key> positional argument.`,
			},
			flags.Provisioner,
			sshProvisionerPasswordFlag,
			flags.NoPassword,
			flags.Insecure,
			flags.Force,
			flags.SSHPOPCert,
			flags.SSHPOPKey,
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func rekeyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	certFile := args.Get(0)
	keyFile := args.Get(1)

	// SSH uses fixed suffixes for public keys and certificates
	var newPubFile, newCertFile, newKeyFile string
	if out := ctx.String("out"); out != "" {
		newPubFile = out + ".pub"
		newCertFile = out + "-cert.pub"
		newKeyFile = out
	} else {
		newPubFile = keyFile + ".pub"
		newCertFile = certFile
		newKeyFile = keyFile
	}

	// Extra flags
	passwordFile := ctx.String("password-file")
	noPassword := ctx.Bool("no-password")
	insecure := ctx.Bool("insecure")

	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	// Load the cert, because we need the serial number.
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, "error reading ssh certificate from %s", certFile)
	}
	sshpub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return errors.Wrapf(err, "error parsing ssh public key from %s", certFile)
	}
	cert, ok := sshpub.(*ssh.Certificate)
	if !ok {
		return errors.New("error casting ssh public key to ssh certificate")
	}
	serial := strconv.FormatUint(cert.Serial, 10)

	ctx.Set("sshpop-cert", certFile)
	ctx.Set("sshpop-key", keyFile)
	token, err := flow.GenerateSSHToken(ctx, serial, cautils.SSHRekeyType, nil, provisioner.TimeDuration{}, provisioner.TimeDuration{})
	if err != nil {
		return err
	}

	caClient, err := flow.GetClient(ctx, token)
	if err != nil {
		return err
	}

	// Generate keypair
	pub, priv, err := keyutil.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return errors.Wrap(err, "error creating public key")
	}

	resp, err := caClient.SSHRekey(&api.SSHRekeyRequest{
		OTT:       token,
		PublicKey: sshPub.Marshal(),
	})
	if err != nil {
		return err
	}

	// Private key (with password unless --no-password --insecure)
	opts := []pemutil.Options{
		pemutil.WithOpenSSH(true),
		pemutil.ToFile(newKeyFile, 0600),
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

	// Write public key
	if err := utils.WriteFile(newPubFile, marshalPublicKey(sshPub, cert.KeyId), 0644); err != nil {
		return err
	}

	// Write certificate
	if err := utils.WriteFile(newCertFile, marshalPublicKey(resp.Certificate, cert.KeyId), 0644); err != nil {
		return err
	}

	// Write renewed identity
	if len(resp.IdentityCertificate) > 0 {
		if err := identity.WriteIdentityCertificate(resp.IdentityCertificate); err != nil {
			return err
		}
	}

	ui.PrintSelected("Private Key", newKeyFile)
	ui.PrintSelected("Public Key", newPubFile)
	ui.PrintSelected("Certificate", newCertFile)

	return nil
}
