package ssh

import (
	"io/ioutil"
	"strconv"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func renewCommand() cli.Command {
	return cli.Command{
		Name:   "renew",
		Action: command.ActionFunc(renewAction),
		Usage:  "renew a SSH certificate using the SSH CA",
		UsageText: `**step ssh renew** <ssh-cert> <ssh-key> <new-ssh-cert>
[**--issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<path>]
[**--password-file**=<path>] [**--offline**] [**--ca-config**=<path>]
[**--force**]`,
		Description: `**step ssh renew** command renews an SSH Cerfificate
using [step certificates](https://github.com/smallstep/certificates).

## POSITIONAL ARGUMENTS

<ssh-cert>
:  The ssh certificate to renew.

<ssh-key>
:  The ssh certificate private key.

<new-ssh-cert>
:  The path where the new SSH Certificate should be written.

## EXAMPLES

Renew an ssh certificate:
'''
$ step ssh renew id_ecdsa-cert.pub id_ecdsa new-id_ecdsa-cer.pub
'''`,
		Flags: []cli.Flag{
			sshProvisionerPasswordFlag,
			flags.Provisioner,
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

func renewAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	certFile := args.Get(0)
	keyFile := args.Get(1)
	newCertFile := args.Get(2)

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
	token, err := flow.GenerateSSHToken(ctx, serial, cautils.SSHRenewType, nil, provisioner.TimeDuration{}, provisioner.TimeDuration{})
	if err != nil {
		return err
	}

	// Prepare retry function
	retryFunc, err := loginOnUnauthorized(ctx)
	if err != nil {
		return err
	}

	caClient, err := flow.GetClient(ctx, token, ca.WithRetryFunc(retryFunc))
	if err != nil {
		return err
	}

	resp, err := caClient.SSHRenew(&api.SSHRenewRequest{
		OTT: token,
	})
	if err != nil {
		return err
	}

	// Write certificate
	if err := utils.WriteFile(newCertFile, marshalPublicKey(resp.Certificate, cert.KeyId), 0644); err != nil {
		return err
	}
	ui.PrintSelected("Certificate", newCertFile)

	return nil
}
