package ssh

import (
	"io/ioutil"
	"strconv"

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
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func rekeyCommand() cli.Command {
	return cli.Command{
		Name:   "rekey",
		Action: command.ActionFunc(rekeyAction),
		Usage:  "rekey a SSH certificate using the SSH CA",
		UsageText: `**step ssh rekey** <ssh-cert> <ssh-key>
[**--new-cert**=<path>] [**--new-key**=<path>]
[**--issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<path>]
[**--password-file**=<path>] [**--offline**] [**--ca-config**=<path>]
[**--force**]`,
		Description: `**step ssh rerekey** command generates a new SSH Certificate
and key using an existing SSH Cerfificate (signed by **step-ca**) as a template.
This command uses [step certificates](https://github.com/smallstep/certificates).

## POSITIONAL ARGUMENTS

<ssh-cert>
:  The ssh certificate to renew.

<ssh-key>
:  The ssh certificate private key.

## EXAMPLES

Rekey an ssh certificate:
'''
$ step ssh rekey id_ecdsa-cert.pub id_ecdsa
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "cert",
				Usage: `The path to the <cert> that should be revoked.`,
			},
			cli.StringFlag{
				Name:  "key",
				Usage: `The <path> to the key corresponding to the cert that should be revoked.`,
			},
			sshProvisionerPasswordFlag,
			flags.Provisioner,
			flags.NoPassword,
			flags.Insecure,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
			flags.Force,
			flags.SSHPOPCert,
			flags.SSHPOPKey,
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

	newCertFile := ctx.String("new-cert")
	newKeyFile := ctx.String("new-key")
	passwordFile := ctx.String("password-file")
	noPassword := ctx.Bool("no-password")
	insecure := ctx.Bool("insecure")
	if len(newCertFile) == 0 {
		newCertFile = certFile
	}
	if len(newKeyFile) == 0 {
		newKeyFile = keyFile
	}
	pubFile := newKeyFile + ".pub"

	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	// Load the cert, because we need the serial number.
	certBytes, err := ioutil.ReadFile(certFile)
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
	pub, priv, err := keys.GenerateDefaultKeyPair()
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
		pemutil.ToFile(newKeyFile, 0600),
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

	if err := utils.WriteFile(pubFile, marshalPublicKey(sshPub, cert.KeyId), 0644); err != nil {
		return err
	}

	// Write certificate
	if err := utils.WriteFile(newCertFile, marshalPublicKey(resp.Certificate, cert.KeyId), 0644); err != nil {
		return err
	}
	ui.PrintSelected("Private Key", newKeyFile)
	ui.PrintSelected("Public Key", pubFile)
	ui.PrintSelected("Certificate", newCertFile)

	return nil
}
