package ssh

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/sshutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

const sshDefaultPath = "/usr/bin/ssh"

type registryResponse struct {
	User     string `json:"user"`
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
	Command  string `json:"cmd"`
	Flags    string `json:"flags"`
}

func proxycommandCommand() cli.Command {
	return cli.Command{
		Name:      "proxycommand",
		Action:    command.ActionFunc(proxycommandAction),
		Usage:     "proxy ssh connections according to the host registry",
		UsageText: `**step ssh proxycommand** <user> <host> <port>`,
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
			cli.StringFlag{
				Name:  "registry",
				Usage: "The <url> of the registration server.",
			},
			cli.StringFlag{
				Name:  "username",
				Usage: "The <user> to authenticate on the registration server.",
			},
			cli.StringFlag{
				Name:  "password",
				Usage: "The <password> to authenticate on the registration server.",
			},
			flags.Provisioner,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
		},
	}
}

func proxycommandAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	user, host, port := args[0], args[1], args[2]

	registry := ctx.String("registry")
	username := ctx.String("username")
	password := ctx.String("password")

	switch {
	case registry == "":
		return errs.RequiredFlag(ctx, "registry")
	case username == "":
		return errs.RequiredFlag(ctx, "username")
	case password == "":
		return errs.RequiredFlag(ctx, "password")
	}

	registryURL, err := url.Parse(registry)
	if err != nil {
		return errors.Wrap(err, "error parsing registry url")
	}

	// Check if user is logged in
	if err := doLoginIfNeeded(ctx, user); err != nil {
		return err
	}

	// Connect to the registration server
	registryURL = registryURL.ResolveReference(&url.URL{
		Path:     path.Join("/auth/bastions", host),
		RawQuery: url.Values{"user": []string{user}}.Encode(),
	})
	registration, err := getRegistryResponse(registryURL.String(), username, password)
	if err != nil {
		return err
	}

	// Connect through bastion
	if registration.Hostname != "" {
		return proxyBastion(registration)
	}

	// Connect directly
	return proxyDirect(host, port)
}

// doLoginIfNeeded check if the user is logged in looking at the ssh agent, if
// it's not it will do the login flow.
func doLoginIfNeeded(ctx *cli.Context, subject string) error {
	agent, err := sshutil.DialAgent()
	if err != nil {
		return err
	}

	client, err := cautils.NewClient(ctx)
	if err != nil {
		return err
	}

	var opts []sshutil.AgentOption
	if roots, err := client.SSHRoots(); err == nil && len(roots.UserKeys) > 0 {
		userKeys := make([]ssh.PublicKey, len(roots.UserKeys))
		for i, uk := range roots.UserKeys {
			userKeys[i] = uk.PublicKey
		}
		opts = append(opts, sshutil.WithSignatureKey(userKeys))
	}

	// Do login flow if key is not in agent
	if _, err := agent.GetSigner(subject, opts...); err != nil {
		flow, err := cautils.NewCertificateFlow(ctx)
		if err != nil {
			return err
		}

		principals := []string{subject}

		// Make sure the validAfter is in the past. It avoids `Certificate
		// invalid: not yet valid` errors if the times are not in sync
		// perfectly.
		validAfter := provisioner.NewTimeDuration(time.Now().Add(-1 * time.Minute))
		validBefore := provisioner.TimeDuration{}

		token, err := flow.GenerateSSHToken(ctx, subject, provisioner.SSHUserCert, principals, validAfter, validBefore)
		if err != nil {
			return err
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

		// Sign certificate in the CA
		resp, err := caClient.SSHSign(&api.SSHSignRequest{
			PublicKey:   sshPub.Marshal(),
			OTT:         token,
			Principals:  principals,
			CertType:    provisioner.SSHUserCert,
			ValidAfter:  validAfter,
			ValidBefore: validBefore,
		})
		if err != nil {
			return err
		}

		// Add certificate and private key to agent
		if err := agent.AddCertificate(subject, resp.Certificate.Certificate, priv); err != nil {
			return err
		}
	}

	return nil
}

func getRegistryResponse(rawurl, username, password string) (registryResponse, error) {
	var Nil registryResponse
	req, err := http.NewRequest("GET", rawurl, http.NoBody)
	if err != nil {
		return Nil, errors.Wrap(err, "error creating request")
	}
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Nil, errors.Wrap(err, "error doing registry request")
	}
	defer resp.Body.Close()

	// Fail or assume no bastion on 404
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusNotFound {
			return Nil, nil
		}
		return Nil, errors.New(http.StatusText(resp.StatusCode))
	}

	// Read response
	var registration registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&registration); err != nil {
		return Nil, errors.Wrap(err, "error decoding registry response")
	}

	return registration, nil
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

func proxyBastion(r registryResponse) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		sshPath = sshDefaultPath
	}

	args := []string{}
	if r.User != "" {
		args = append(args, "-l", r.User)
	}
	if r.Port != "" {
		args = append(args, "-p", r.Port)
	}
	if r.Flags != "" {
		// BUG(mariano): This is a naive way of doing it as it doesn't
		// support strings, but it should work for most of the cases in ssh.
		// For more advance cases the package
		// github.com/kballard/go-shellquote can be used.
		fields := strings.Fields(r.Flags)
		args = append(args, fields...)
	}
	args = append(args, r.Hostname)
	if r.Command != "" {
		args = append(args, r.Command)
	}
	exec.Exec(sshPath, args...)
	return nil
}
