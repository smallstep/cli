package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"golang.org/x/crypto/ssh/terminal"
)

// In command line utilities, it is a de facto standard that a hyphen "-"
// indicates STDIN as a file to be read.
const stdinFilename = "-"

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

// ReadPasswordGenerate asks the user for a password using the given prompt.
// **Do Not** use this method from within another script. It may print a
// generated password to stdout. Instead use ReadPassword.
//
// This solution works on darwin and linux, but it might not work on other
// OSs.
func ReadPasswordGenerate(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	pass, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Fprintln(os.Stderr)
	if pass == nil {
		_pass, err := randutil.ASCII(32)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		pass = []byte(_pass)
		fmt.Fprintf(os.Stderr, "\npassword: %s\n\n", pass)
	}
	return pass, errors.Wrap(err, "error reading password")
}

// ReadPasswordFromFile reads and returns the password from the given filename.
// The contents of the file will be trimmed at the right.
func ReadPasswordFromFile(filename string) ([]byte, error) {
	password, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}
	password = bytes.TrimRightFunc(password, unicode.IsSpace)
	return password, nil
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

var _osStdin = os.Stdin

// ReadFile returns the contents of the file identified by name. It reads from
// STDIN if name is a hyphen ("-").
func ReadFile(name string) (b []byte, err error) {
	if name == stdinFilename {
		name = "/dev/stdin"
		b, err = ioutil.ReadAll(_osStdin)
	} else {
		b, err = ioutil.ReadFile(name)
	}
	if err != nil {
		return nil, errs.FileError(err, name)
	}
	return b, nil
}
