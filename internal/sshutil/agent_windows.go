package sshutil

import (
	"context"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/agent"
)

// dialAgent returns an ssh.Agent client. It uses the SSH_AUTH_SOCK to connect
// to the agent.
func dialAgent() (*Agent, error) {
	// Override the default windows openssh-ssh-agent pipe
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		// Attempt unix sockets for environments like cygwin.
		if conn, err := net.Dial("unix", socket); err == nil {
			return &Agent{
				ExtendedAgent: agent.NewClient(conn),
				Conn:          conn,
			}, nil
		}

		// Connect to Windows pipe at the supplied address
		conn, err := winio.DialPipeContext(context.Background(), socket)
		if err != nil {
			return nil, errors.Wrap(err, "error connecting with ssh-agent at pipe specified by environment variable SSH_AUTH_SOCK")
		}
		return &Agent{
			ExtendedAgent: agent.NewClient(conn),
			Conn:          conn,
		}, nil
	}

	// DEFAULT: Windows OpenSSH agent
	conn, err := winio.DialPipeContext(context.Background(), `\\.\\pipe\\openssh-ssh-agent`)
	if err != nil {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}
	return &Agent{
		ExtendedAgent: agent.NewClient(conn),
		Conn:          conn,
	}, nil
}
