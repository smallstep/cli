package sshutil

import (
	"context"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/agent"
)

// dialAgent returns an ssh.Agent client. It uses the SSH_AUTH_SOCK to connect
// to the agent.
func dialAgent() (*Agent, error) {
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := winio.DialPipeContext(ctx, "\\.\\pipe\\openssh-ssh-agent")
	if err != nil {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}
	return &Agent{
		ExtendedAgent: agent.NewClient(conn),
		Conn:          conn,
	}, nil
}
