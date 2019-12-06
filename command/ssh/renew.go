package ssh

import (
	"io/ioutil"
	"strconv"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
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
		UsageText: `**step ssh renew** <ssh-cert> <ssh-key>
		[**--out**=<file>] [**--issuer**=<name>] [**--password-file**=<path>]
		[**--force**] [**--ca-url**=<uri>] [**--root**=<path>]
		[**--offline**] [**--ca-config**=<path>]`,
		Description: `**step ssh renew** command renews an SSH Cerfificate
using [step certificates](https://github.com/smallstep/certificates). 
It writes the new certificate to disk - either overwriting <ssh-cert> or
using a new file when the **--out**=<file> flag is used.

## POSITIONAL ARGUMENTS

<ssh-cert>
:  The ssh certificate to renew.

<ssh-key>
:  The ssh certificate private key.

## EXAMPLES

Renew an ssh certificate overwriting the previous one:
'''
$ step ssh renew -f id_ecdsa-cert.pub id_ecdsa
'''

Renew an ssh certificate with a custom out file:
'''
$ step ssh renew -out new-id_ecdsa-cer.pub id_ecdsa-cert.pub id_ecdsa
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <ssh-cert> positional argument",
			},
			flags.Provisioner,
			sshProvisionerPasswordFlag,
			flags.Force,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
			flags.SSHPOPCert,
			flags.SSHPOPKey,
		},
	}
}

func renewAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	certFile := args.Get(0)
	keyFile := args.Get(1)

	// Flags
	outFile := ctx.String("out")
	if outFile == "" {
		outFile = certFile
	}

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

	caClient, err := flow.GetClient(ctx, token)
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
	if err := utils.WriteFile(outFile, marshalPublicKey(resp.Certificate, cert.KeyId), 0644); err != nil {
		return err
	}
	ui.PrintSelected("Certificate", outFile)

	return nil
}
