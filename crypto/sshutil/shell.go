package sshutil

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
)

// ProxyCommand replaces %%, %h, %p, and %r in the given command.
//  %%  A literal `%`.
//  %h  The remote hostname.
//  %p  The remote port.
//  %r  The remote username.
func ProxyCommand(cmd, user, host, port string) string {
	cmd = strings.Replace(cmd, "%%", "%", -1)
	cmd = strings.Replace(cmd, "%h", host, -1)
	cmd = strings.Replace(cmd, "%p", port, -1)
	return strings.Replace(cmd, "%r", user, -1)
}

// ShellOption is the type used to add new options to the shell.
type ShellOption func(s *Shell) error

// WithAuthMethod adds a new ssh.AuthMethod to the shell.
func WithAuthMethod(am ssh.AuthMethod) ShellOption {
	return func(s *Shell) error {
		s.authMethods = append(s.authMethods, am)
		return nil
	}
}

// WithSigner adds the given signer as an ssh.AuthMethod.
func WithSigner(signer ssh.Signer) ShellOption {
	return func(s *Shell) error {
		s.authMethods = append(s.authMethods, ssh.PublicKeys(signer))
		return nil
	}
}

// WithCertificate adds a signer with the given certificate as an
// ssh.AuthMethod.
func WithCertificate(cert *ssh.Certificate, priv interface{}) ShellOption {
	return func(s *Shell) error {
		signer, err := NewCertSigner(cert, priv)
		if err != nil {
			return err
		}
		s.authMethods = append(s.authMethods, ssh.PublicKeys(signer))
		return nil
	}
}

// WithAddUser uses the given provisioner certificate to add an user in the
// server.
func WithAddUser(user string, cert *ssh.Certificate, priv interface{}) ShellOption {
	return func(s *Shell) error {
		return errors.New("not yet implemented")
	}
}

// WithBastion forward the connection through the given bastion address.
func WithBastion(user, address, command string) ShellOption {
	return func(s *Shell) error {
		s.dialer = func(callback ssh.HostKeyCallback) (*ssh.Client, error) {
			// Connect to bastion
			bastion, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
				User:            user,
				Auth:            s.authMethods,
				HostKeyCallback: callback,
			})
			if err != nil {
				return nil, errors.Wrapf(err, "error connecting %s", address)
			}
			// Connect from bastion to final destination
			conn, err := bastion.Dial("tcp", s.address)
			if err != nil {
				return nil, errors.Wrapf(err, "error connecting %s", s.address)
			}
			c, chans, reqs, err := ssh.NewClientConn(conn, s.address, &ssh.ClientConfig{
				User:            s.user,
				Auth:            s.authMethods,
				HostKeyCallback: callback,
			})
			if err != nil {
				return nil, err
			}
			return ssh.NewClient(c, chans, reqs), nil
		}
		return nil
	}
}

// WithProxyCommand forwards the connection through the given command
func WithProxyCommand(command string) ShellOption {
	return func(s *Shell) error {
		s.dialer = func(callback ssh.HostKeyCallback) (*ssh.Client, error) {
			host, port, err := net.SplitHostPort(s.address)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing address")
			}
			pr, pw := net.Pipe()
			args := strings.Fields(ProxyCommand(command, s.user, host, port))
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdin = pw
			cmd.Stdout = pw
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				return nil, errors.Wrap(err, "error running proxy command")
			}
			c, chans, reqs, err := ssh.NewClientConn(pr, s.address, &ssh.ClientConfig{
				User:            s.user,
				Auth:            s.authMethods,
				HostKeyCallback: callback,
			})
			if err != nil {
				return nil, err
			}
			return ssh.NewClient(c, chans, reqs), nil
		}
		return nil
	}
}

// withDefaultAuthMethod adds the ssh.Agent as an ssh.AuthMethod.
func withDefaultAuthMethod() ShellOption {
	return func(s *Shell) error {
		agent, err := DialAgent()
		if err != nil {
			return err
		}
		s.authMethods = append(s.authMethods, agent.AuthMethod())
		return nil
	}
}

// withDefaultDialer adds a direct connection dialer.
func withDefaultDialer(user, address string) ShellOption {
	return func(s *Shell) error {
		s.dialer = func(callback ssh.HostKeyCallback) (*ssh.Client, error) {
			client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
				User:            user,
				Auth:            s.authMethods,
				HostKeyCallback: callback,
			})
			if err != nil {
				return nil, errors.Wrapf(err, "error connecting %s", address)
			}
			return client, nil
		}
		return nil
	}
}

func formatAddress(address string) string {
	if _, _, err := net.SplitHostPort(address); err != nil {
		address += ":22"
	}
	return address
}

// Shell implements a remote shell to an SSH server using x/crypto/ssh
type Shell struct {
	user        string
	address     string
	authMethods []ssh.AuthMethod
	signer      ssh.Signer
	client      *ssh.Client
	dialer      func(callback ssh.HostKeyCallback) (*ssh.Client, error)
}

// NewShell initializes a new shell to the given address.
func NewShell(user, address string, opts ...ShellOption) (*Shell, error) {
	address = formatAddress(address)

	home, err := config.Home()
	if err != nil {
		return nil, err
	}

	// Use known_host as HostKeyCallback
	knownHosts, err := knownhosts.New(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		return nil, errors.Wrap(err, "error reading known_hosts")
	}

	shell := &Shell{
		user:    user,
		address: address,
	}
	if err := shell.apply(opts); err != nil {
		return nil, err
	}

	if len(shell.authMethods) == 0 {
		if err := withDefaultAuthMethod()(shell); err != nil {
			return nil, err
		}
	}
	if shell.dialer == nil {
		if err := withDefaultDialer(user, address)(shell); err != nil {
			return nil, err
		}
	}

	if shell.client, err = shell.dialer(knownHosts); err != nil {
		return nil, err
	}

	return shell, nil
}

func (s *Shell) apply(opts []ShellOption) error {
	for _, fn := range opts {
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}

// Close finalizes the connection.
func (s *Shell) Close() error {
	return s.client.Close()
}

// Run runs cmd on the remote host.
func (s *Shell) Run(cmd string) error {
	// Create a session
	session, err := s.client.NewSession()
	if err != nil {
		return errors.Wrap(err, "error creating a session")
	}
	defer session.Close()

	return session.Run(cmd)
}

// RemoteShell starts a login shell on the remote host.
func (s *Shell) RemoteShell() error {
	// Create a session
	session, err := s.client.NewSession()
	if err != nil {
		return errors.Wrap(err, "error creating a session")
	}
	defer session.Close()

	var fallback bool
	if fd := int(os.Stdin.Fd()); terminal.IsTerminal(fd) {
		// Put terminal in raw mode
		if originalState, err := terminal.MakeRaw(fd); err != nil {
			fallback = true
		} else {
			defer terminal.Restore(fd, originalState)

			// Get terminal size
			w, h, err := terminal.GetSize(fd)
			if err != nil {
				w, h = 80, 40
			}

			// Request pseudo terminal
			if err := requestPty(session, h, w, ssh.TerminalModes{
				ssh.ECHO:          1,     // enable echoing
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			}); err != nil {
				return err
			}
		}
	} else {
		fallback = true
	}

	if fallback {
		if err := requestPty(session, 40, 80, ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}); err != nil {
			return errors.Wrap(err, "error getting pseudo terminal")
		}
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "cannot setup stdin for session")
	}
	go io.Copy(stdin, os.Stdin)

	stdout, err := session.StdoutPipe()
	if err != nil {
		return errors.Wrap(err, "cannot setup stdout for session")
	}
	go io.Copy(os.Stdout, stdout)

	stderr, err := session.StderrPipe()
	if err != nil {
		return errors.Wrap(err, "cannot setup stderr for session")
	}
	go io.Copy(os.Stderr, stderr)

	// Start remote shell
	if err := session.Shell(); err != nil {
		return errors.Wrap(err, "error starting remote shell")
	}

	return session.Wait()
}

// LocalForward creates a local listener in the bindAddress forwarding the
// packages to the remote hostAddress.
func (s *Shell) LocalForward(bindNetwork, bindAddress, hostNetwork, hostAddress string) error {
	l, err := net.Listen(bindNetwork, bindAddress)
	if err != nil {
		return errors.Wrapf(err, "error listening on %s", bindAddress)
	}
	defer l.Close()

	remote, err := s.client.Dial(hostNetwork, hostAddress)
	if err != nil {
		return errors.Wrapf(err, "error dialing %s", hostAddress)
	}
	defer remote.Close()

	for {
		local, err := l.Accept()
		if err != nil {
			return errors.Wrapf(err, "error connecting to %s", bindAddress)
		}
		handleConn(local, remote)
	}
}

// RemoteForward creates a remote listener in the bindAddress and forwards the
// packages to the local hostAddress.
func (s *Shell) RemoteForward(bindNetwork, bindAddress, hostNetwork, hostAddress string) error {
	l, err := s.client.Listen(bindNetwork, bindAddress)
	if err != nil {
		return errors.Wrapf(err, "error listening on %s", bindAddress)
	}
	defer l.Close()

	for {
		local, err := net.Dial(hostNetwork, hostAddress)
		if err != nil {
			return errors.Wrapf(err, "error dialing %s", hostAddress)
		}
		remote, err := l.Accept()
		if err != nil {
			return errors.Wrapf(err, "error connection to %s", bindAddress)
		}
		handleConn(remote, local)
	}
}

func requestPty(session *ssh.Session, h, w int, modes ssh.TerminalModes) (err error) {
	var terms []string
	switch t := os.Getenv("TERM"); t {
	case "", "xterm-256color":
		terms = append(terms, "xterm-256color", "xterm")
	case "xterm":
		terms = append(terms, "xterm")
	default:
		terms = append(terms, t, "xterm-256color", "xterm")
	}
	for _, t := range terms {
		if err = session.RequestPty(t, h, w, modes); err == nil {
			return
		}
	}
	return errors.Wrap(err, "error getting pseudo terminal")
}

func handleConn(local, remote net.Conn) {
	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(local, remote)
		if err != nil {
			log.Println("error while copy remote->local:", err)
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, local)
		if err != nil {
			log.Println(err)
		}
		chDone <- true
	}()

	<-chDone
}
