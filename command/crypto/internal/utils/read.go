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
	"golang.org/x/crypto/ssh/terminal"
)

// ReadAll returns a slice of bytes with the content of the given reader.
func ReadAll(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	return b, errors.Wrap(err, "error reading data")
}

// ReadString reads one line from the given io.Reader.
func ReadString(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	str, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", errors.Wrap(err, "error reading string")
	}
	return strings.TrimSpace(str), nil
}

// ReadPassword asks the user for a password using the given prompt. If the
// program is receiving data from STDIN using a pipe, we cannot use
// terminal.ReadPassword on STDIN and we need to open the tty and read from
// it.
//
// This solution works on darwin and linux, but it might not work on other
// OSs.
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	var fd int
	if terminal.IsTerminal(syscall.Stdin) {
		fd = syscall.Stdin
	} else {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, errors.Wrap(err, "error allocating terminal")
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}

	pass, err := terminal.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return pass, errors.Wrap(err, "error reading password")
}

// ReadInput from stdin if something is detected or ask the user for an input
// using the given prompt.
func ReadInput(prompt string) ([]byte, error) {
	st, err := os.Stdin.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "error reading data")
	}

	if st.Size() > 0 {
		return ReadAll(os.Stdin)
	}

	return ReadPassword(prompt)
}
