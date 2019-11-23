// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

package sshutil

import (
	"net"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/agent"
)

// dialAgent returns an ssh.Agent client. It uses the SSH_AUTH_SOCK to connect
// to the agent.
func dialAgent() (*Agent, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}
	return &Agent{
		ExtendedAgent: agent.NewClient(conn),
		Conn:          conn,
	}, nil
}
