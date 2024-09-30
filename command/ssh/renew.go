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

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
)

func renewCommand() cli.Command {
	return cli.Command{
		Name:   "renew",
		Action: command.ActionFunc(renewAction),
		Usage:  "renew a SSH certificate using the SSH CA",
		UsageText: `**step ssh renew** <ssh-cert> <ssh-key> [**--out**=<file>]
[**--issuer**=<name>] [**--password-file**=<file>] [**--force**] [**--offline**]
[**--ca-config**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,
		Description: `**step ssh renew** command renews an SSH Host Certificate
using [step certificates](https://github.com/smallstep/certificates).
It writes the new certificate to disk - either overwriting <ssh-cert> or
using a new file when the **--out**=<file> flag is used. This command cannot
be used to renew SSH User Certificates.

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
				Usage: "The new certificate <file>. Defaults to overwriting the <ssh-cert> positional argument",
			},
			flags.Provisioner,
			sshProvisionerPasswordFlag,
			flags.SSHPOPCert,
			flags.SSHPOPKey,
			flags.Force,
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
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

	// Write renewed identity
	if len(resp.IdentityCertificate) > 0 {
		if err := identity.WriteIdentityCertificate(resp.IdentityCertificate); err != nil {
			return err
		}
	}

	ui.PrintSelected("Certificate", outFile)

	return nil
}
