package sshutil

import (
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrKeyNotFound is the error returned if a key is not found.
var ErrKeyNotFound = errors.New("key not found")

// Agent represents a client to an ssh.Agent.
type Agent struct {
	agent.ExtendedAgent
	Conn net.Conn
}

// DialAgent returns an ssh.Agent client. It uses the SSH_AUTH_SOCK to connect
// to the agent.
func DialAgent() (*Agent, error) {
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

// Close closes the connection to the agent.
func (a *Agent) Close() error {
	return a.Conn.Close()
}

// GetKey retrieves a key from the agent by the given comment.
func (a *Agent) GetKey(comment string) (*agent.Key, error) {
	keys, err := a.List()
	if err != nil {
		return nil, errors.Wrap(err, "error listing keys")
	}
	for _, key := range keys {
		if key.Comment == comment {
			return key, nil
		}
	}
	return nil, ErrKeyNotFound
}

// AddCertificate adds the given certificate to the agent.
func (a *Agent) AddCertificate(subject string, cert *ssh.Certificate, priv interface{}) error {
	var (
		lifetime uint64
		now      = uint64(time.Now().Unix())
	)
	if cert.ValidBefore == ssh.CertTimeInfinity {
		// 0 indicates that the certificate should never expire from the agent.
		lifetime = 0
	} else if cert.ValidBefore <= now {
		return errors.New("error adding certificate to ssh agent - certificate is already expired")
	} else {
		lifetime = cert.ValidBefore - now
	}
	return errors.Wrap(a.Add(agent.AddedKey{
		PrivateKey:   priv,
		Certificate:  cert,
		Comment:      subject,
		LifetimeSecs: uint32(lifetime),
	}), "error adding key to agent")
}
