package ssh

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/utils/cautils"
)

// init creates and registers the ssh command
func init() {
	cmd := cli.Command{
		Name:      "ssh",
		Usage:     "create and manage ssh certificates",
		UsageText: "step ssh <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ssh** command group provides facilities to sign SSH certificates.

## EXAMPLES

Generate a new SSH key pair and user certificate:
'''
$ step ssh certificate joe@work id_ecdsa
'''

Generate a new SSH key pair and host certificate:
'''
$ step ssh certificate --host internal.example.com ssh_host_ecdsa_key
'''

Add a new user certificate to the agent:
'''
$ step ssh login joe@example.com
'''

Remove a certificate from the agent:
'''
$ step ssh logout joe@example.com
'''

List all keys in the agent:
'''
$ step ssh list
'''

Configure a user environment with the SSH templates:
'''
$ step ssh config
'''

Inspect an ssh certificate file:
'''
$ step ssh inspect id_ecdsa-cert.pub
'''

Inspect an ssh certificate in the agent:
'''
$ step ssh list --raw joe@example.com | step ssh inspect
'''

List all the hosts you have access to:
'''
$ step ssh hosts
'''

Login into one host:
'''
$ ssh internal.example.com
'''`,
		Subcommands: cli.Commands{
			certificateCommand(),
			checkHostCommand(),
			configCommand(),
			fingerPrintCommand(),
			hostsCommand(),
			inspectCommand(),
			listCommand(),
			loginCommand(),
			logoutCommand(),
			needsRenewalCommand(),
			// proxyCommand(),
			proxycommandCommand(),
			rekeyCommand(),
			renewCommand(),
			revokeCommand(),
		},
	}

	command.Register(cmd)
}

var (
	sshPrincipalFlag = cli.StringSliceFlag{
		Name: "principal,n",
		Usage: `Add the specified principal (user or host <name>s) to the certificate request.
		This flag can be used multiple times. However, it cannot be used in conjunction
		with '--token' when requesting certificates from OIDC, JWK, and X5C provisioners, or
		from any provisioner with 'disableCustomSANs' set to 'true'. These provisioners will
		use the contents of the token to determine the principals.`,
	}

	sshUserPrincipalFlag = cli.StringSliceFlag{
		Name: "principal,n",
		Usage: `Add the specified principal (username) to the certificate request.
		This flag can be used multiple times. However, it cannot be used in conjunction
		with '--token' when requesting certificates from OIDC, JWK, and X5C provisioners, or
		from any provisioner with 'disableCustomSANs' set to 'true'. These provisioners will
		use the contents of the token to determine the principals.`,
	}

	sshHostFlag = cli.BoolFlag{
		Name:  "host",
		Usage: `Create a host certificate instead of a user certificate.`,
	}

	sshHostIDFlag = cli.StringFlag{
		Name: "host-id",
		Usage: `Specify a <UUID> to identify the host rather than using an auto-generated UUID.
		If "machine" is passed, derive a UUID from "/etc/machine-id."`,
	}

	sshSignFlag = cli.BoolFlag{
		Name:  "sign",
		Usage: `Sign the public key passed as an argument instead of creating one.`,
	}

	sshPasswordFileFlag = cli.StringFlag{
		Name:  "password-file",
		Usage: `The path to the <file> containing the password to encrypt the private key.`,
	}

	sshProvisionerPasswordFlag = cli.StringFlag{
		Name: "provisioner-password-file",
		Usage: `The path to the <file> containing the password to decrypt the one-time token
		generating key.`,
	}

	sshAddUserFlag = cli.BoolFlag{
		Name:  "add-user",
		Usage: `Create a user provisioner certificate used to create a new user.`,
	}

	sshPrivateKeyFlag = cli.StringFlag{
		Name: "private-key",
		Usage: `When signing an existing public key, use this flag to specify the corresponding
private key so that the pair can be added to an SSH Agent.`,
	}
)

func loginOnUnauthorized(ctx *cli.Context) (ca.RetryFunc, error) {
	templateData, err := flags.ParseTemplateData(ctx)
	if err != nil {
		return nil, err
	}

	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return nil, err
	}

	client, err := cautils.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return func(code int) bool {
		if code != http.StatusUnauthorized {
			return false
		}

		fail := func(err error) bool {
			ui.Printf("{{ \"%v\" | red }}\n", err)
			return false
		}

		// Generate OIDC token
		tok, err := flow.GenerateIdentityToken(ctx)
		if err != nil {
			return fail(err)
		}
		jwt, err := token.ParseInsecure(tok)
		if err != nil {
			return fail(err)
		}
		if jwt.Payload.Email == "" {
			return fail(errors.New("error creating identity token: email address cannot be empty"))
		}

		// Generate SSH Keys
		pub, priv, err := keyutil.GenerateDefaultKeyPair()
		if err != nil {
			return fail(err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return fail(err)
		}

		// Generate identity CSR (x509)
		identityCSR, identityKey, err := ca.CreateIdentityRequest(jwt.Payload.Email)
		if err != nil {
			return fail(err)
		}

		resp, err := client.SSHSign(&api.SSHSignRequest{
			PublicKey:    sshPub.Marshal(),
			OTT:          tok,
			CertType:     provisioner.SSHUserCert,
			KeyID:        jwt.Payload.Email,
			IdentityCSR:  *identityCSR,
			TemplateData: templateData,
		})
		if err != nil {
			return fail(err)
		}

		// Write x509 identity certificate
		if err := ca.WriteDefaultIdentity(resp.IdentityCertificate, identityKey); err != nil {
			return fail(err)
		}

		// Add ssh certificate to the agent, ignore errors.
		if agent, err := sshutil.DialAgent(); err == nil {
			agent.AddCertificate(jwt.Payload.Email, resp.Certificate.Certificate, priv)
		}

		return true
	}, nil
}

// tokenEmail returns if the token payload has an email address. This is
// mainly used on OIDC token.
func tokenEmail(s string) (string, bool) {
	jwt, err := token.ParseInsecure(s)
	if err != nil {
		return "", false
	}
	return jwt.Payload.Email, jwt.Payload.Email != ""
}

// tokenSubject extracts the token subject.
func tokenSubject(s string) (string, bool) {
	jwt, err := token.ParseInsecure(s)
	if err != nil {
		return "", false
	}
	return jwt.Payload.Subject, jwt.Payload.Subject != ""
}

func sshConfigErr(err error) error {
	return &errs.Error{
		Err: err,
		Msg: "There is a problem with your step configuration. Please run 'step ssh config'.",
	}
}

func contactAdminErr(err error) error {
	return &errs.Error{
		Err: err,
		Msg: "There is a problem with your step configuration. Please contact an administrator.",
	}
}

func debugErr(err error) error {
	return &errs.Error{
		Err: err,
		Msg: "An error occurred in the step process. Please contact an administrator.",
	}
}

// createPrincipalsFromSubject create default principals names for a subject. By
// default it would be the sanitized version of the subject, but if the subject
// is an email it will add the local part if it's different and the email
// address.
func createPrincipalsFromSubject(subject string) []string {
	name := provisioner.SanitizeSSHUserPrincipal(subject)
	principals := []string{name}
	if i := strings.LastIndex(subject, "@"); i >= 0 {
		if local := subject[:i]; !strings.EqualFold(local, name) {
			principals = append(principals, local)
		}
	}
	// Append the original subject if different.
	if subject != name {
		principals = append(principals, subject)
	}
	return principals
}
