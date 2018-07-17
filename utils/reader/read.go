package reader

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

var passwordLength = 64

type retryError struct{}

func (re *retryError) Error() string {
	return "Need to retry"
}

// DefaultOnEmpty replaces pointer value with default value if the value is an empty string.
func DefaultOnEmpty(def string) func(*string, string) error {
	return func(ptr *string, key string) error {
		if ptr == nil {
			return errors.Errorf("pointer cannot be nil")
		}

		if len(*ptr) == 0 {
			*ptr = def
		}
		return nil
	}
}

// CurrentDirectoryOnEmpty replaces pointer value with current directory
// if the value is an empty string.
func CurrentDirectoryOnEmpty(ptr *string, key string) error {
	if ptr == nil {
		return errors.Errorf("pointer cannot be nil")
	}

	if len(*ptr) == 0 {
		*ptr = "."
	}
	return nil
}

// FailOnEmpty returns an error if the pointer value is an empty string.
func FailOnEmpty(ptr *string, key string) error {
	if ptr == nil {
		return errors.Errorf("pointer cannot be nil")
	}
	if len(*ptr) == 0 {
		return errors.Errorf("%s parameter cannot be empty", key)
	}
	return nil
}

// GeneratePasswordOnEmpty replaces pointer value with a newly generated
// password if the value is an empty string.
func GeneratePasswordOnEmpty(ptr *string, key string) error {
	if ptr == nil {
		return errors.Errorf("pointer cannot be nil")
	}

	if len(*ptr) == 0 {
		var err error
		if *ptr, err = crypto.GenerateRandomRestrictedString(passwordLength); err != nil {
			return errors.Wrapf(err, "Failed to generate %s", key)
		}
		fmt.Printf("\n\n%s: %s\n\n", key, *ptr)
		return nil
	}
	fmt.Println()
	return nil
}

// RetryOnEmpty returns a retryError if the value in the ptr is an empty string.
func RetryOnEmpty(ptr *string, key string) error {
	if ptr == nil {
		return errors.Errorf("pointer cannot be nil")
	}

	if len(*ptr) == 0 {
		return &retryError{}
	}
	return nil
}

type valid func(*string, string) error

// ReadPassword reads password into ptr from stdin - input silenced.
func ReadPassword(prompt string, ptr *string, key string, v valid) error {
	return _readPassword(prompt, os.Stdout, ptr, key, v)
}

// ReadPasswordSubtle reads password from stdin, but prompt goes to stderr
// rather than stdout.
func ReadPasswordSubtle(prompt string, ptr *string, key string, v valid) error {
	return _readPassword(prompt, os.Stderr, ptr, key, v)
}

func _readPassword(prompt string, w io.Writer, ptr *string, key string, v valid) error {
	if ptr == nil {
		return errors.Errorf("pointer cannot be nil")
	}

	fmt.Fprintf(w, prompt)
	temp, err := terminal.ReadPassword(int(syscall.Stdin))
	// Need to add newline, b/c it will be swallowed by ReadPassword.
	if w == os.Stderr {
		fmt.Fprintf(w, "\n")
	}
	if err != nil {
		return errors.WithStack(err)
	}
	*ptr = strings.TrimSpace(string(temp))

	if err = v(ptr, key); err == nil {
		return nil
	}
	switch err.(type) {
	case *retryError:
		return _readPassword(prompt, w, ptr, key, v)
	default:
		return errors.WithStack(err)
	}
}

// ReadString reads string into ptr from stdin.
func ReadString(reader *bufio.Reader, prompt string, ptr *string, key string, v valid) error {
	if reader == nil {
		return errors.Errorf("reader cannot be nil")
	}
	if ptr == nil {
		return errors.Errorf("pointer cannot be nil")
	}

	fmt.Printf(prompt)
	temp, err := reader.ReadString('\n')
	if err != nil {
		return errors.WithStack(err)
	}
	*ptr = strings.TrimSpace(temp)

	if err = v(ptr, key); err == nil {
		return nil
	}
	switch err.(type) {
	case *retryError:
		return ReadString(reader, prompt, ptr, key, v)
	default:
		return errors.WithStack(err)
	}
}
