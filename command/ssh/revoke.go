package ssh

import (
	"os"
	"strconv"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	cmdca "github.com/smallstep/cli/command/ca"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
)

func revokeCommand() cli.Command {
	return cli.Command{
		Name:   "revoke",
		Action: command.ActionFunc(revokeAction),
		Usage:  "revoke a SSH certificate using the SSH CA",
		UsageText: `**step ssh revoke** <serial-number>
[**--token**=<token>]  [**--issuer**=<name>] [**--set**=<key=value>]
[**--set-file**=<file>] [**--password-file**=<file>] [**--reason**=<string>]
[**--reasonCode**=<code>] [**--sshpop-cert**=<file>] [**--sshpop-key**=<key>]
[**--offline**] [**--ca-config**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--context**=<name>]`,

		Description: `**step ssh revoke** command revokes an SSH Certificate
using [step certificates](https://github.com/smallstep/certificates).

## POSITIONAL ARGUMENTS

<serial-number>
:  The serial number of the SSH certificate to revoke.

## EXAMPLES

revoke an ssh certificate:
'''
$ step ssh revoke 3997477584487736496
'''`,
		Flags: []cli.Flag{
			flags.Token,
			sshProvisionerPasswordFlag,
			flags.Provisioner,
			flags.TemplateSet,
			flags.TemplateSetFile,
			flags.SSHPOPCert,
			flags.SSHPOPKey,
			cli.StringFlag{
				Name:  "reason",
				Usage: `The <string> representing the reason for which the cert is being revoked.`,
			},
			cli.StringFlag{
				Name:  "reasonCode",
				Value: "",
				Usage: `The <reasonCode> specifies the reason for revocation - chose from a list of
common revocation reasons. If unset, the default is Unspecified.

: <reasonCode> can be a number from 0-9 or a case insensitive string matching
one of the following options:

    **Unspecified**
    :  No reason given (Default -- reasonCode=0).

    **KeyCompromise**
    :  The key is believed to have been compromised (reasonCode=1).

    **CACompromise**
    :  The issuing Certificate Authority itself has been compromised (reasonCode=2).

    **AffiliationChanged**
    :  The certificate contained affiliation information, for example, it may
have been an EV certificate and the associated business is no longer owned by
the same entity (reasonCode=3).

    **Superseded**
    :  The certificate is being replaced (reasonCode=4).

    **CessationOfOperation**
    :  If a CA is decommissioned, no longer to be used, the CA's certificate
should be revoked with this reason code. Do not revoke the CA's certificate if
the CA no longer issues new certificates, yet still publishes CRLs for the
currently issued certificates (reasonCode=5).

    **CertificateHold**
    :  A temporary revocation that indicates that a CA will not vouch for a
certificate at a specific point in time. Once a certificate is revoked with a
CertificateHold reason code, the certificate can then be revoked with another
Reason Code, or unrevoked and returned to use (reasonCode=6).

    **RemoveFromCRL**
    :  If a certificate is revoked with the CertificateHold reason code, it is
possible to "unrevoke" a certificate. The unrevoking process still lists the
certificate in the CRL, but with the reason code set to RemoveFromCRL.
Note: This is specific to the CertificateHold reason and is only used in DeltaCRLs
(reasonCode=8).

    **PrivilegeWithdrawn**
    :  The right to represent the given entity was revoked for some reason
(reasonCode=9).

    **AACompromise**
    :   It is known or suspected that aspects of the AA validated in the
attribute certificate have been compromised (reasonCode=10).
`,
			},
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func revokeAction(ctx *cli.Context) error {
	args := ctx.Args()
	token := ctx.String("token")
	var serial string

	switch ctx.NArg() {
	case 0:
		certFile := ctx.String("sshpop-cert")
		keyFile := ctx.String("sshpop-key")
		if certFile == "" || keyFile == "" {
			return errors.New("--sshpop-cert and --sshpop-key must be supplied if serial number is not supplied as first argument")
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
		serial = strconv.FormatUint(cert.Serial, 10)
	case 1:
		serial = args.Get(0)
	default:
		return errs.TooManyArguments(ctx)
	}

	reason := ctx.String("reason")
	// Convert the reasonCode flag to an OCSP revocation code.
	reasonCode, err := cmdca.ReasonCodeToNum(ctx.String("reasonCode"))
	if err != nil {
		return err
	}

	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	if token == "" {
		token, err = flow.GenerateSSHToken(ctx, serial, cautils.SSHRevokeType, nil, provisioner.TimeDuration{}, provisioner.TimeDuration{})
		if err != nil {
			return err
		}
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

	_, err = caClient.SSHRevoke(&api.SSHRevokeRequest{
		Serial:     serial,
		Reason:     reason,
		ReasonCode: reasonCode,
		OTT:        token,
		Passive:    true,
	})
	if err != nil {
		return err
	}

	ui.Printf("SSH Certificate with Serial Number %s has been revoked.\n", serial)
	return nil
}
