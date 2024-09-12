package ssh

import (
	"crypto"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils/cautils"
)

const sshDefaultPath = "/usr/bin/ssh"

func proxycommandCommand() cli.Command {
	return cli.Command{
		Name:   "proxycommand",
		Action: command.ActionFunc(proxycommandAction),
		Usage:  "proxy ssh connections according to the host registry",
		UsageText: `**step ssh proxycommand** <user> <host> <port>
[**--provisioner**=<name>] [**--set**=<key=value>] [**--set-file**=<file>]
[**--console**] [**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
		Description: `**step ssh proxycommand** looks into the host registry
and proxies the ssh connection according to its configuration. This command
is used in the ssh client config with <ProxyCommand> keyword.

This command will add the user to the ssh-agent if necessary.

## POSITIONAL ARGUMENTS

<user>
:  The remote username, and the subject used to login.

<host>
:  The host to connect to.

<port>
:  The port to connect to.`,
		Flags: []cli.Flag{
			flags.Provisioner,
			flags.ProvisionerPasswordFileWithAlias,
			flags.TemplateSet,
			flags.TemplateSetFile,
			flags.Console,
			flags.Offline,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func proxycommandAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	user, host, port := args[0], args[1], args[2]

	// Check if user is logged in
	if err := doLoginIfNeeded(ctx, user); err != nil {
		return err
	}

	// Get the configured bastion if any
	r, err := getBastion(ctx, user, host)
	if err != nil {
		return err
	}

	// Connect through bastion
	if r.Bastion != nil && r.Bastion.Hostname != "" {
		return proxyBastion(r, user, host, port)
	}

	// Connect directly
	return proxyDirect(host, port)
}

// doLoginIfNeeded check if the user is logged in looking at the ssh agent, if
// it's not it will do the login flow.
func doLoginIfNeeded(ctx *cli.Context, subject string) error {
	templateData, err := flags.ParseTemplateData(ctx)
	if err != nil {
		return err
	}

	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}

	client, err := cautils.NewClient(ctx)
	if err != nil {
		return err
	}

	// Check if a user key exists
	if roots, err := client.SSHRoots(); err == nil && len(roots.UserKeys) > 0 {
		userKeys := make([]ssh.PublicKey, len(roots.UserKeys))
		for i, uk := range roots.UserKeys {
			userKeys[i] = uk.PublicKey
		}
		exists, err := agent.HasKeys(sshutil.WithSignatureKey(userKeys), sshutil.WithRemoveExpiredCerts(time.Now()))
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}

	// Do login flow
	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	// There's not need to sanitize the principal, it should come from ssh.
	principals := []string{subject}

	// Make sure the validAfter is in the past. It avoids `Certificate
	// invalid: not yet valid` errors if the times are not in sync
	// perfectly.
	validAfter := provisioner.NewTimeDuration(time.Now().Add(-1 * time.Minute))
	validBefore := provisioner.TimeDuration{}

	token, err := flow.GenerateSSHToken(ctx, subject, cautils.SSHUserSignType, principals, validAfter, validBefore)
	if err != nil {
		return err
	}

	// NOTE: For OIDC tokens the subject should always be the email. The
	// provisioner is responsible for loading and setting the principals with
	// the application of an Identity function.
	if email, ok := tokenEmail(token); ok {
		subject = email
	}

	caClient, err := flow.GetClient(ctx, token)
	if err != nil {
		return err
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

	// Generate keypair
	pub, priv, err := keyutil.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return errors.Wrap(err, "error creating public key")
	}

	// Sign certificate in the CA
	resp, err := caClient.SSHSign(&api.SSHSignRequest{
		PublicKey:    sshPub.Marshal(),
		OTT:          token,
		Principals:   principals,
		CertType:     provisioner.SSHUserCert,
		KeyID:        subject,
		ValidAfter:   validAfter,
		ValidBefore:  validBefore,
		IdentityCSR:  identityCSR,
		TemplateData: templateData,
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

	// Add certificate and private key to agent
	return agent.AddCertificate(subject, resp.Certificate.Certificate, priv)
}

func getBastion(ctx *cli.Context, user, host string) (*api.SSHBastionResponse, error) {
	client, err := cautils.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.SSHBastion(&api.SSHBastionRequest{
		User:     user,
		Hostname: host,
	})
}

func proxyDirect(host, port string) error {
	address := net.JoinHostPort(host, port)
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return errors.Wrap(err, "error resolving address")
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return errors.Wrapf(err, "error connecting to %s", address)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		io.Copy(conn, os.Stdin)
		conn.CloseWrite()
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		io.Copy(os.Stdout, conn)
		conn.CloseRead()
		wg.Done()
	}()

	wg.Wait()
	return nil
}

func proxyBastion(r *api.SSHBastionResponse, user, host, port string) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		sshPath = sshDefaultPath
	}

	args := []string{}
	if r.Bastion.User != "" {
		args = append(args, "-l", r.Bastion.User)
	}
	if r.Bastion.Port != "" {
		args = append(args, "-p", r.Bastion.Port)
	}
	if r.Bastion.Flags != "" {
		// BUG(mariano): This is a naive way of doing it as it doesn't
		// support strings, but it should work for most of the cases in ssh.
		// For more advance cases the package
		// github.com/kballard/go-shellquote can be used.
		fields := strings.Fields(r.Bastion.Flags)
		args = append(args, fields...)
	}
	args = append(args, r.Bastion.Hostname)
	if r.Bastion.Command != "" {
		args = append(args, sshutil.ProxyCommand(r.Bastion.Command, user, host, port))
	} else {
		args = append(args, "nc", host, port)
	}
	exec.Exec(sshPath, args...)
	return nil
}
