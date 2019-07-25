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

func sshCertificateCommand() cli.Command {
	return cli.Command{
		Name:        "ssh-certificate",
		Action:      command.ActionFunc(sshCertificateAction),
		Usage:       "sign an ssh certificate",
		UsageText:   `**step ca ssh-certificate** <key-id> <keyFile>`,
		Description: `**step ca ssh-certificate** command ...`,
		Flags: []cli.Flag{
			tokenFlag,
			// cli.StringFlag{
			// 	Name: "type",
			// 	Usage: `The certificate type to issue (<user|host>). With a certificate clients or
			// 	servers may trust only the CA key and verify its signature on a certificate
			// 	rather than trusting many user/host keys.`,
			// 	Value: provisioner.SSHUserCert,
			// },
			cli.StringSliceFlag{
				Name: "principal,n",
				Usage: `Add the principals (users or hosts) that the token is authorized to
				request. The signing request using this token won't be able to add
				extra names. Use the '--principal' flag multiple times to configure
				multiple ones. The '--principal' flag and the '--token' flag are
				mutually exlusive.`,
			},
			cli.BoolFlag{
				Name:  "host",
				Usage: `Create a host certificate instead of a user certificate.`,
			},
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
	principals := ctx.StringSlice("principal")
	validAfter, validBefore, err := parseTimeDuration(ctx)
	if err != nil {
		return err
	}

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

	pub, priv, err := keys.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return errors.Wrap(err, "error creating public key")
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
	if err := utils.WriteFile(crtFile, marshalPublicKey(resp.Certificate, subject), 0644); err != nil {
		return err
	}
	ui.PrintSelected("Certificate", crtFile)

	if pubFile != "" {
		if err := utils.WriteFile(pubFile, marshalPublicKey(sshPub, subject), 0644); err != nil {
			return err
		}
		ui.PrintSelected("Public Key", pubFile)
	}

	_, err = pemutil.Serialize(priv, pemutil.ToFile(keyFile, 0600))
	if err != nil {
		return err
	}
	ui.PrintSelected("Private Key", keyFile)

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
