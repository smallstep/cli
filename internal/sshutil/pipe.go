package sshutil

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// defaultPipeName is the default Windows OpenSSH agent pipe
	defaultPipeName = `\\.\\pipe\\openssh-ssh-agent`
)

func determineWindowsPipeName() string {
	var (
		homeDrive = "C:"
		homePath  = os.Getenv("HOMEPATH")
	)

	if hd := os.Getenv("HOMEDRIVE"); hd != "" {
		homeDrive = hd
	}

	sshAgentConfigFile := filepath.Join(homeDrive, homePath, ".ssh", "config")

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
			line := strings.TrimSpace(sc.Text())
			if len(line) > 15 && strings.HasPrefix(line, "IdentityAgent") {
				pipeName = re2.ReplaceAllString(re.ReplaceAllString(line[14:], "\\"), "")
				break
			}
		}
	}

	return
}
