package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/ui"
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

	str, err := ui.Prompt(fmt.Sprintf("Would you like to overwrite %s [y/n]", filename), ui.WithValidateYesNo())
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(str)) {
	case "y", "yes":
	case "n", "no":
		return ErrFileExists
	}

	return ioutil.WriteFile(filename, data, perm)
}

// AppendNewLine appends the given data at the end of the file. If the last
// character of the file does not contain an LF it prepends it to the data.
func AppendNewLine(filename string, data []byte, perm os.FileMode) error {
	f, err := OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	// Read last character
	if st, err := f.File.Stat(); err == nil && st.Size() != 0 {
		last := make([]byte, 1)
		f.Seek(-1, 2)
		f.Read(last)
		if last[0] != '\n' {
			f.WriteString("\n")
		}
	}
	f.Write(data)
	return f.Close()
}
