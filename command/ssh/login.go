package ssh

import (
	"crypto"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func loginCommand() cli.Command {
	return cli.Command{
		Name:   "login",
		Action: command.ActionFunc(loginAction),
		Usage:  "adds a SSH certificate into the authentication agent",
		UsageText: `**step ssh login** <identity>
		[**--token**=<token>] [**--provisioner**=<name>] [**--provisioner-password-file**=<file>]
		[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
		[**--force**] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--offline**] [**--ca-config**=<path>]`,
		Description: `**step ssh login** generates a new SSH key pair and send a request to [step
certificates](https://github.com/smallstep/certificates) to sign a user
certificate. This certificate will be automatically added to the SSH agent.

With a certificate servers may trust only the CA key and verify its signature on
a certificate rather than trusting many user keys.

## POSITIONAL ARGUMENTS

<identity>
:  The certificate identity. If no principals are passed we will use
the identity as a principal, if it has the format abc@def then the
principal will be abc.

## EXAMPLES

Request a new SSH certificate and add it to the agent:
'''
$ step ssh login joe@example.com
'''

Request a new SSH certificate valid only for 1h:
'''
$ step ssh login --not-after 1h joe@smallstep.com
'''`,
		Flags: []cli.Flag{
			flags.Token,
			sshAddUserFlag,
			flags.Provisioner,
			flags.ProvisionerPasswordFile,
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

	// Hack to make the flag "password-file" the content of
	// "provisioner-password-file" so the token command works as expected
	ctx.Set("password-file", ctx.String("provisioner-password-file"))

	// Connect to the SSH agent.
	// step ssh login requires an ssh agent.
	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}

	// Check for a previous key signed by the CA.
	if !force {
		client, err := cautils.NewClient(ctx)
		if err != nil {
			return err
		}
		opts := []sshutil.AgentOption{
			sshutil.WithRemoveExpiredCerts(time.Now()),
		}
		if roots, err := client.SSHRoots(); err == nil && len(roots.UserKeys) > 0 {
			userKeys := make([]ssh.PublicKey, len(roots.UserKeys))
			for i, uk := range roots.UserKeys {
				userKeys[i] = uk.PublicKey
			}
			opts = append(opts, sshutil.WithSignatureKey(userKeys))
		}

		// Just return if key is present
		if _, err := agent.GetKey(subject, opts...); err == nil {
			ui.Printf("The key %s is already present in the SSH agent.\n", subject)
			return nil
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

		if token, err = flow.GenerateSSHToken(ctx, subject, cautils.SSHUserSignType, principals, validAfter, validBefore); err != nil {
			return err
		}
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
		identityCSR = *csr
		identityKey = key
	}

	// NOTE: For OIDC token the principals should be completely empty. The OIDC
	// provisioner is responsible for setting default principals by using an
	// identity function.
	if email, ok := tokenHasEmail(token); ok {
		principals = []string{}
		subject = email
	}

	resp, err := caClient.SSHSign(&api.SSHSignRequest{
		PublicKey:        sshPub.Marshal(),
		OTT:              token,
		Principals:       principals,
		CertType:         provisioner.SSHUserCert,
		ValidAfter:       validAfter,
		ValidBefore:      validBefore,
		AddUserPublicKey: sshAuPubBytes,
		IdentityCSR:      identityCSR,
	})
	if err != nil {
		return err
	}

	// Write x509 identity certificate
	if version.RequireClientAuthentication {
		if err := ca.WriteDefaultIdentity(resp.IdentityCertificate, identityKey); err != nil {
			return err
		}
	}

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

	return nil
}
