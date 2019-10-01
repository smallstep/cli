package ssh

import (
	"time"

	"github.com/smallstep/cli/crypto/sshutil"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func loginCommand() cli.Command {
	return cli.Command{
		Name:      "login",
		Action:    command.ActionFunc(loginAction),
		Usage:     "adds a SSH certificate into the authentication agent",
		UsageText: `**step ssh login** <principal>`,
		Description: `**step ssh login** command ...

## POSITIONAL ARGUMENTS

TODO

## EXAMPLES

TODO`,
		Flags: []cli.Flag{
			flags.Token,
			sshAddUserFlag,
			sshPasswordFileFlag,
			sshConnectFlag,
			cli.StringFlag{
				Name:  "via,bastion",
				Usage: "TODO",
			},
			cli.StringFlag{
				Name:  "via-command,bastion-command",
				Usage: "TODO",
				Value: "nc -q0 %h %p",
			},
			cli.StringFlag{
				Name:  "proxy,p",
				Usage: "TODO",
			},
			flags.Provisioner,
			flags.NotBefore,
			flags.NotAfter,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
			flags.Force,
		},
	}
}

func loginAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	// Arguments
	subject := ctx.Args().First()
	user := provisioner.SanitizeSSHUserPrincipal(subject)
	principals := []string{user}

	// Flags
	token := ctx.String("token")
	isAddUser := ctx.Bool("add-user")
	force := ctx.Bool("force")
	validAfter, validBefore, err := flags.ParseTimeDuration(ctx)
	if err != nil {
		return err
	}

	// SSH client flags
	address := ctx.String("connect")
	proxyCommand := ctx.String("proxy")
	bastionAddress := ctx.String("bastion")
	bastionCommand := ctx.String("bastion-command")

	switch {
	case proxyCommand != "" && bastionAddress != "":
		return errs.IncompatibleFlagWithFlag(ctx, "proxy", "bastion")
	case bastionAddress != "" && bastionCommand == "":
		return errs.RequiredWithFlag(ctx, "bastion", "bastion-command")
	}

	// Connect with SSH agent if available
	agent, agentErr := sshutil.DialAgent()

	// Connect to the remote shell using the previous certificate in the agent
	if agent != nil && !force {
		if signer, err := agent.GetSigner(subject); err == nil {
			// Just return if key is present
			if address == "" {
				ui.Printf("The key %s is already present in the SSH agent.\n", subject)
				return nil
			}

			// Use signer to connect to the remote server
			opts := []sshutil.ShellOption{
				sshutil.WithSigner(signer),
			}
			if proxyCommand != "" {
				opts = append(opts, sshutil.WithProxyCommand(proxyCommand))
			}
			if bastionAddress != "" {
				opts = append(opts, sshutil.WithBastion(user, bastionAddress, bastionCommand))
			}

			shell, err := sshutil.NewShell(user, address, opts...)
			if err != nil {
				return err
			}
			return shell.RemoteShell()
		}
	}

	// Do step-certificates flow
	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}
	if len(token) == 0 {
		// Make sure the validAfter is in the past. It avoids `Certificate
		// invalid: not yet valid` errors if the times are not in sync
		// perfectly.
		if validAfter.IsZero() {
			validAfter = provisioner.NewTimeDuration(time.Now().Add(-1 * time.Minute))
		}

		if token, err = flow.GenerateSSHToken(ctx, subject, provisioner.SSHUserCert, principals, validAfter, validBefore); err != nil {
			return err
		}
	}

	caClient, err := flow.GetClient(ctx, subject, token)
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

	resp, err := caClient.SignSSH(&api.SignSSHRequest{
		PublicKey:        sshPub.Marshal(),
		OTT:              token,
		Principals:       principals,
		CertType:         provisioner.SSHUserCert,
		ValidAfter:       validAfter,
		ValidBefore:      validBefore,
		AddUserPublicKey: sshAuPubBytes,
	})
	if err != nil {
		return err
	}

	if agent == nil {
		ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, agentErr)
	} else {
		// Attempt to add key to agent if private key defined.
		if err := agent.AddCertificate(subject, resp.Certificate.Certificate, priv); err != nil {
			ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
		} else {
			ui.PrintSelected("SSH Agent", "yes")
		}
		if isAddUser {
			if err := agent.AddCertificate(subject, resp.AddUserCertificate.Certificate, auPriv); err != nil {
				ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
			} else {
				ui.PrintSelected("SSH Agent", "yes")
			}
		}
	}

	// Connect to the remote shell using the new certificate
	if address != "" {
		if isAddUser {
			auCert := resp.AddUserCertificate.Certificate
			auOpts := []sshutil.ShellOption{
				sshutil.WithCertificate(auCert, auPriv),
			}
			shell, err := sshutil.NewShell(auCert.ValidPrincipals[0], address, auOpts...)
			if err != nil {
				return err
			}
			if err := shell.Run(""); err != nil {
				return err
			}
		}

		opts := []sshutil.ShellOption{
			sshutil.WithCertificate(resp.Certificate.Certificate, priv),
		}
		if proxyCommand != "" {
			opts = append(opts, sshutil.WithProxyCommand(proxyCommand))
		}
		if bastionAddress != "" {
			opts = append(opts, sshutil.WithBastion(user, bastionAddress, bastionCommand))
		}

		shell, err := sshutil.NewShell(user, address, opts...)
		if err != nil {
			return err
		}
		return shell.RemoteShell()
	}

	return nil
}
