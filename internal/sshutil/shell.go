package sshutil

import (
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"github.com/smallstep/cli-utils/step"
)

// ProxyCommand replaces %%, %h, %p, and %r in the given command.
//
//	%%  A literal `%`.
//	%h  The remote hostname.
//	%p  The remote port.
//	%r  The remote username.
func ProxyCommand(cmd, user, host, port string) string {
	cmd = strings.ReplaceAll(cmd, "%%", "%")
	cmd = strings.ReplaceAll(cmd, "%h", host)
	cmd = strings.ReplaceAll(cmd, "%p", port)
	return strings.ReplaceAll(cmd, "%r", user)
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
	client      *ssh.Client
	dialer      func(callback ssh.HostKeyCallback) (*ssh.Client, error)
}

// NewShell initializes a new shell to the given address.
func NewShell(user, address string, opts ...ShellOption) (*Shell, error) {
	address = formatAddress(address)

	// Use known_host as HostKeyCallback
	knownHosts, err := knownhosts.New(filepath.Join(step.Home(), ".ssh", "known_hosts"))
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
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		// Put terminal in raw mode
		if originalState, err := term.MakeRaw(fd); err != nil {
			fallback = true
		} else {
			defer term.Restore(fd, originalState)

			// Get terminal size
			w, h, err := term.GetSize(fd)
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
			return nil
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
