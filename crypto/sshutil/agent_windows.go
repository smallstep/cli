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
	// Attempt unix sockets for environments like cygwin.
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if conn, err := net.Dial("unix", socket); err == nil {
			return &Agent{
				ExtendedAgent: agent.NewClient(conn),
				Conn:          conn,
			}, nil
		}
	}

	// Windows OpenSSH agent
	conn, err := winio.DialPipeContext(context.Background(), `\\.\\pipe\\openssh-ssh-agent`)
	if err != nil {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}
	return &Agent{
		ExtendedAgent: agent.NewClient(conn),
		Conn:          conn,
	}, nil
}
