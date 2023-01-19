package ssh

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/maps"

	"go.step.sm/cli-utils/command"

	"github.com/smallstep/cli/utils"
)

func verifyCommand() cli.Command {
	return cli.Command{
		Name:      "verify",
		Action:    command.ActionFunc(verifyAction),
		Usage:     "verify an ssh certificate",
		UsageText: `**step ssh verify** <crt-file> <ca-file>`,
		Description: `**step ssh verify** command ...
format.

`,
	}
}

func verifyAction(ctx *cli.Context) error {

	// TODO: validation of args; allow caFile to be interpreted as directory
	var (
		certFile = ctx.Args().Get(0)
		caFile   = ctx.Args().Get(1)
	)

	certBytes, err := utils.ReadFile(certFile)
	if err != nil {
		return err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		// Attempt to parse the key without the type.
		certBytes = bytes.TrimSpace(certBytes)
		keyBytes := make([]byte, base64.StdEncoding.DecodedLen(len(certBytes)))
		n, err := base64.StdEncoding.Decode(keyBytes, certBytes)
		if err != nil {
			return errors.Wrap(err, "error parsing ssh certificate")
		}
		if pub, err = ssh.ParsePublicKey(keyBytes[:n]); err != nil {
			return errors.Wrap(err, "error parsing ssh certificate")
		}
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.Errorf("error decoding ssh certificate: %T is not an *ssh.Certificate", pub)
	}

	// TODO: add additional config? This could include a revocation check.
	checker := &ssh.CertChecker{
		SupportedCriticalOptions: maps.Keys(cert.CriticalOptions), // allow any option in the certificate
	}

	var principal string
	if len(cert.ValidPrincipals) > 0 {
		principal = cert.ValidPrincipals[0]
	}

	// check critical options, principal, validity and signature
	if err := checker.CheckCert(principal, cert); err != nil {
		return fmt.Errorf("error verifying ssh certificate: %w", err)
	}

	caBytes, err := utils.ReadFile(caFile)
	if err != nil {
		return err
	}

	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caBytes)
	if err != nil {
		// Attempt to parse the key without the type.
		certBytes = bytes.TrimSpace(caBytes)
		keyBytes := make([]byte, base64.StdEncoding.DecodedLen(len(certBytes)))
		n, err := base64.StdEncoding.Decode(keyBytes, certBytes)
		if err != nil {
			return errors.Wrap(err, "error parsing ssh CA certificate")
		}
		if caPub, err = ssh.ParsePublicKey(keyBytes[:n]); err != nil {
			return errors.Wrap(err, "error parsing ssh CA certificate")
		}
	}

	// check the certificate was signed by the SSH CA provided
	caFP := ssh.FingerprintSHA256(caPub)
	certSignerFP := ssh.FingerprintSHA256(cert.SignatureKey)
	if certSignerFP != caFP {
		return fmt.Errorf("ssh certificate signed by %q does not equal ssh CA %q", certSignerFP, caFP)
	}

	return nil
}
