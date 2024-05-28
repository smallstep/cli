package sshutil

import (
	"bufio"
	"context"
	"net"
	"os"
	"regexp"

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

	homepath := os.Getenv("HOMEPATH")
	sshagentfile := string(homepath) + "\\.ssh\\config"

	// DEFAULT: Windows OpenSSH agent
	pipename := "\\\\.\\pipe\\ssh-agent"

	file, err := os.Open(sshagentfile)
	if err == nil {
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			var line = sc.Text()
			if len(line) > 15 {
				compare := line[0:13]
				if compare == "IdentityAgent" {
					temp := line[14:len(line)]
					re := regexp.MustCompile(`/`)
					re2 := regexp.MustCompile(`[\s\"]*`)
					pipename = re2.ReplaceAllString(re.ReplaceAllString(temp, "\\"), "")
				}
			}
		}
	}
	if conn, err := winio.DialPipeContext(context.Background(), pipename); err == nil {
		return &Agent{
			ExtendedAgent: agent.NewClient(conn),
			Conn:          conn,
		}, nil
	} else {
		return nil, errors.Wrap(err, "error connecting with ssh-agent")
	}
}
