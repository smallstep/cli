package utils

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
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

	return ui.PromptPassword(prompt)
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
