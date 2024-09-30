package ssh

import (
	"crypto"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
)

func loginCommand() cli.Command {
	return cli.Command{
		Name:   "login",
		Action: command.ActionFunc(loginAction),
		Usage:  "adds a SSH certificate into the authentication agent",
		UsageText: `**step ssh login** [<identity>]
[**--token**=<token>] [**--provisioner**=<name>] [**--provisioner-password-file**=<file>]
[**--principal**=<string>] [**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--kty**=<key-type>] [**--curve**=<curve>] [**--size**=<size>] [**--comment**=<comment>]
[**--set**=<key=value>] [**--set-file**=<file>] [**--console**] [**--force**] [**--insecure**]
[**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
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
$ step ssh login bob
'''

Request a new SSH certificate using an OIDC provisioner:
'''
$ step ssh login
'''

Request a new SSH certificate valid only for 1h:
'''
$ step ssh login --not-after 1h alice
'''

Request a new SSH certificate with multiple principals:
'''
$ step ssh login --principal admin --principal bob bob@smallstep.com
'''

Request a new SSH certificate and set a custom comment in the agent
'''
$ step ssh login --comment my-custom-comment bob@smallstep.com
'''

Request a new SSH certificate with an EC key and P-521 curve:
'''
$  step ssh certificate --kty EC --curve "P-521" mariano@work id_ecdsa
'''

Request a new SSH certificate with an Octet Key Pair and Ed25519 curve:
'''
$  step ssh certificate --kty OKP --curve Ed25519 mariano@work id_ed25519
'''`,
		Flags: []cli.Flag{
			flags.Token,
			sshAddUserFlag,
			sshUserPrincipalFlag,
			flags.Identity,
			flags.Provisioner,
			flags.ProvisionerPasswordFileWithAlias,
			flags.NotBefore,
			flags.NotAfter,
			flags.TemplateSet,
			flags.TemplateSetFile,
			flags.Console,
			flags.Force,
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
			flags.Comment,
			flags.KTY,
			flags.Curve,
			flags.Size,
			flags.Insecure,
		},
	}
}

func loginAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	// Arguments
	subject := ctx.Args().First()
	if subject == "" {
		subject = ctx.String("identity")
	}

	principals := ctx.StringSlice("principal")
	if subject != "" && len(principals) == 0 {
		principals = []string{subject}
	}

	comment := ctx.String("comment")
	if comment == "" {
		comment = subject
	}

	// Flags
	token := ctx.String("token")
	isAddUser := ctx.Bool("add-user")
	force := ctx.Bool("force")
	insecure := ctx.Bool("insecure")
	validAfter, validBefore, err := flags.ParseTimeDuration(ctx)
	if err != nil {
		return err
	}
	templateData, err := flags.ParseTemplateData(ctx)
	if err != nil {
		return err
	}

	kty, curve, size, err := utils.GetKeyDetailsFromCLI(ctx, insecure, "kty", "curve", "size")
	if err != nil {
		return err
	}

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
		if key, err := agent.GetKey(comment, opts...); err == nil {
			ui.Printf("The key %s is already present in the SSH agent.\n", key.String())
			return nil
		}
	}

	// Do step-certificates flow
	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}
	if token == "" {
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

	pub, priv, err := keyutil.GenerateKeyPair(kty, curve, size)
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
		auPub, auPriv, err = keyutil.GenerateKeyPair(kty, curve, size)
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

	// NOTE: For OIDC tokens the subject should always be the email. The
	// provisioner is responsible for loading and setting the principals with
	// the application of an Identity function.
	if email, ok := tokenEmail(token); ok {
		subject = email
	} else if subject == "" {
		// For non-oidc tokens we will use the token subject.
		if sub, ok := tokenSubject(token); ok {
			subject = sub
		}
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

	resp, err := caClient.SSHSign(&api.SSHSignRequest{
		PublicKey:        sshPub.Marshal(),
		OTT:              token,
		Principals:       principals,
		CertType:         provisioner.SSHUserCert,
		KeyID:            subject,
		ValidAfter:       validAfter,
		ValidBefore:      validBefore,
		AddUserPublicKey: sshAuPubBytes,
		IdentityCSR:      identityCSR,
		TemplateData:     templateData,
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
	if err := agent.AddCertificate(comment, resp.Certificate.Certificate, priv); err != nil {
		ui.Printf(`{{ "%s" | red }} {{ "SSH Agent:" | bold }} %v`+"\n", ui.IconBad, err)
	} else {
		ui.PrintSelected("SSH Agent", "yes")
	}
	if isAddUser {
		if resp.AddUserCertificate == nil {
			ui.Printf(`{{ "%s" | red }} {{ "Add User Certificate:" | bold }} failed to create a provisioner certificate`+"\n", ui.IconBad)
		} else if err := agent.AddCertificate(comment, resp.AddUserCertificate.Certificate, auPriv); err != nil {
			ui.Printf(`{{ "%s" | red }} {{ "Add User Certificate:" | bold }} %v`+"\n", ui.IconBad, err)
		} else {
			ui.PrintSelected("Add User Certificate", "yes")
		}
	}

	return nil
}
