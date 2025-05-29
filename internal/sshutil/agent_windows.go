package sshutil

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
			return nil, errors.Wrap(err, fmt.Sprintf("failed to connect to SSH agent at SSH_AUTH_SOCK=%s", socket))
		}

		return &Agent{
			ExtendedAgent: agent.NewClient(conn),
			Conn:          conn,
		}, nil
	}

	pipeName := determineWindowsPipeName()
	conn, err := winio.DialPipeContext(context.Background(), pipeName)
	if err != nil {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}

	return &Agent{
		ExtendedAgent: agent.NewClient(conn),
		Conn:          conn,
	}, nil
}

const (
	// defaultPipeName is the default Windows OpenSSH agent pipe
	defaultPipeName = `\\.\\pipe\\openssh-ssh-agent`
)

func determineWindowsPipeName() string {
	homePath := os.Getenv("HOMEPATH") // TODO(hs): add default if not set?
	sshAgentConfigFile := filepath.Join(homePath, ".ssh", "config")

	if pipeName := readWindowsPipeNameFrom(sshAgentConfigFile); pipeName != "" {
		return pipeName
	}

	return defaultPipeName
}

var (
	re  = regexp.MustCompile(`/`)
	re2 = regexp.MustCompile(`[\s\"]*`)
)

func readWindowsPipeNameFrom(configFile string) (pipeName string) {
	file, err := os.Open(configFile)
	if err == nil {
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			line := sc.Text()
			if len(line) > 15 && strings.HasPrefix(line, "IdentityAgent") {
				pipeName = re2.ReplaceAllString(re.ReplaceAllString(line[14:], "\\"), "")
				break
			}
		}
	}

	return
}
