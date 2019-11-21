package sshutil

import (
	"bytes"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type options struct {
	filterBySignatureKey func(*agent.Key) bool
}

func newOptions(opts []AgentOption) *options {
	o := new(options)
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// AgentOption is the type used for variadic options in Agent methods.
type AgentOption func(o *options)

// WithSignatureKey filters certificate not signed by the given signing keys.
func WithSignatureKey(keys []ssh.PublicKey) AgentOption {
	signingKeys := make([][]byte, len(keys))
	for i, k := range keys {
		signingKeys[i] = k.Marshal()
	}
	return func(o *options) {
		o.filterBySignatureKey = func(k *agent.Key) bool {
			cert, err := ParseCertificate(k.Marshal())
			if err != nil {
				return false
			}
			b := cert.SignatureKey.Marshal()
			for _, sb := range signingKeys {
				if bytes.Equal(b, sb) {
					return true
				}
			}
			return false
		}
	}
}

// ErrNotFound is the error returned if a something is not found.
var ErrNotFound = errors.New("not found")

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

// AuthMethod returns the ssh.Agent as an ssh.AuthMethod.
func (a *Agent) AuthMethod() ssh.AuthMethod {
	return ssh.PublicKeysCallback(a.Signers)
}

// ListKeys returns the list of keys in the agent.
func (a *Agent) ListKeys(opts ...AgentOption) ([]*agent.Key, error) {
	o := newOptions(opts)
	keys, err := a.List()
	if err != nil {
		return nil, errors.Wrap(err, "error listing keys")
	}
	var list []*agent.Key
	for _, key := range keys {
		if o.filterBySignatureKey == nil || o.filterBySignatureKey(key) {
			list = append(list, key)
		}
	}
	return list, nil
}

// ListCertificates returns the list of certificates in the agent.
func (a *Agent) ListCertificates(opts ...AgentOption) ([]*ssh.Certificate, error) {
	keys, err := a.ListKeys(opts...)
	if err != nil {
		return nil, err
	}
	var list []*ssh.Certificate
	for _, key := range keys {
		if cert, err := ParseCertificate(key.Marshal()); err == nil {
			list = append(list, cert)
		}
	}
	return list, nil
}

// GetKey retrieves a key from the agent by the given comment.
func (a *Agent) GetKey(comment string, opts ...AgentOption) (*agent.Key, error) {
	o := newOptions(opts)
	keys, err := a.List()
	if err != nil {
		return nil, errors.Wrap(err, "error listing keys")
	}
	for _, key := range keys {
		if key.Comment == comment {
			if o.filterBySignatureKey == nil || o.filterBySignatureKey(key) {
				return key, nil
			}
		}
	}
	return nil, ErrNotFound
}

// GetSigner returns a signer that has a key with the given comment.
func (a *Agent) GetSigner(comment string, opts ...AgentOption) (ssh.Signer, error) {
	key, err := a.GetKey(comment, opts...)
	if err != nil {
		return nil, err
	}

	signers, err := a.Signers()
	if err != nil {
		return nil, errors.Wrap(err, "error listing signers")
	}

	keyBytes := key.Marshal()
	for _, sig := range signers {
		if bytes.Equal(keyBytes, sig.PublicKey().Marshal()) {
			return sig, nil
		}
	}

	return nil, ErrNotFound
}

// RemoveKeys removes the keys with the given comment from the agent.
func (a *Agent) RemoveKeys(comment string, opts ...AgentOption) error {
	o := newOptions(opts)
	keys, err := a.List()
	if err != nil {
		return errors.Wrap(err, "error listing keys")
	}

	for _, key := range keys {
		if key.Comment == comment {
			if o.filterBySignatureKey == nil || o.filterBySignatureKey(key) {
				if err := a.Remove(key); err != nil {
					return errors.Wrap(err, "error removing key")
				}
			}
		}
	}

	return nil
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
