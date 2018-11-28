package utils

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	// ErrFileExists is the error returned if a file exists.
	ErrFileExists = errors.New("file exists")

	// ErrIsDir is the error returned if the file is a directory.
	ErrIsDir = errors.New("file is a directory")
)

// WriteFile wraps ioutil.WriteFile with a prompt to overwrite a file if
// the file exists. It returns ErrFileExists if the user picks to not overwrite
// the file. If force is set to true, the prompt will not be presented and the
// file if exists will be overwritten.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	if command.IsForce() {
		return ioutil.WriteFile(filename, data, perm)
	}

	st, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return ioutil.WriteFile(filename, data, perm)
		}
		return errors.Wrapf(err, "error reading information for %s", filename)
	}

	if st.IsDir() {
		return ErrIsDir
	}

	// The file exists
	var r io.Reader
	if terminal.IsTerminal(syscall.Stdin) {
		r = os.Stdin
	} else {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return errors.Wrap(err, "error allocating terminal")
		}
		r = tty
		defer tty.Close()
	}

	br := bufio.NewReader(r)
	for cont := true; cont; {
		fmt.Fprintf(os.Stderr, "Would you like to overwrite %s [Y/n]: ", filename)
		str, err := br.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "error reading line")
		}
		str = strings.ToLower(strings.TrimSpace(str))
		switch str {
		case "", "y", "yes":
			cont = false
		case "n", "no":
			return ErrFileExists
		}
	}

	return ioutil.WriteFile(filename, data, perm)
}
