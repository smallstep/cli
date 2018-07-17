package reader

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/bouk/monkey"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
)

func Test_CurrentDirectoryOnEmpty(t *testing.T) {
	// nil pointer
	var ptr *string
	if err := CurrentDirectoryOnEmpty(ptr, ""); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// empty string
	temp := ""
	ptr = &temp
	if err := CurrentDirectoryOnEmpty(ptr, ""); err == nil {
		if ptr == nil {
			t.Errorf("should not be nil")
		} else if strings.Compare(*ptr, ".") != 0 {
			t.Errorf("data mismatch -- expected: `%s`, but got: `%s`",
				".", *ptr)
		}
	} else {
		t.Errorf("CurrentDirectoryOnEmpty error: %s", err)
	}

	// populated string
	temp = "shake and bake"
	ptr = &temp
	if err := CurrentDirectoryOnEmpty(ptr, ""); err == nil {
		if ptr == nil {
			t.Errorf("should not be nil")
		} else if strings.Compare(*ptr, temp) != 0 {
			t.Errorf("data mismatch -- expected: `%s`, but got: `%s`",
				temp, *ptr)
		}
	} else {
		t.Errorf("CurrentDirectoryOnEmpty error: %s", err)
	}
}

func Test_FailOnEmpty(t *testing.T) {
	key := "Country"

	// nil pointer
	if err := FailOnEmpty(nil, key); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// failure on empty ptr string value
	empty := ""
	ptr := &empty
	if err := FailOnEmpty(ptr, key); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := fmt.Sprintf("%s parameter cannot be empty", key)
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// no change unpopulated string
	ptr = &key
	if err := FailOnEmpty(ptr, key); err == nil {
		if *ptr != key {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				key, *ptr)
		}
	} else {
		t.Errorf("FailOnEmpty error: %s", err)
	}
}

func Test_GeneratePasswordOnEmpty(t *testing.T) {
	// nil pointer
	var ptr *string
	if err := GeneratePasswordOnEmpty(ptr, ""); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// empty string
	temp := ""
	ptr = &temp
	if err := GeneratePasswordOnEmpty(ptr, ""); err == nil {
		if ptr == nil {
			t.Errorf("should not be nil")
		} else if len(*ptr) != passwordLength {
			t.Errorf("password length mismatch -- expected: `%d`, but got: `%d`",
				passwordLength, len(*ptr))
		}
	} else {
		t.Errorf("CurrentDirectoryOnEmpty error: %s", err)
	}

	// populated string
	temp = "shake and bake"
	ptr = &temp
	if err := GeneratePasswordOnEmpty(ptr, "password"); err == nil {
		if *ptr != temp {
			t.Errorf("data mismatch -- expected: `%s`, but got: `%s`",
				temp, *ptr)
		}
	} else {
		t.Errorf("GeneratePasswordOnEmpty error: %s", err)
	}
}

type Reader struct {
	read string
	done bool
}

func NewReader(toRead string) *Reader {
	return &Reader{toRead, false}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	if r.done {
		return 0, io.EOF
	}
	for i, b := range []byte(r.read) {
		p[i] = b
	}
	r.done = true
	return len(r.read), nil
}

type ErrorReader struct {
	read string
	done bool
}

func NewErrorReader(toRead string) *ErrorReader {
	return &ErrorReader{toRead, false}
}

func (r *ErrorReader) Read(p []byte) (n int, err error) {
	return 0, errors.Errorf("bad read")
}

func Test_ReadString(t *testing.T) {
	// nil reader
	if err := ReadString(nil, "", nil, "", CurrentDirectoryOnEmpty); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "reader cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// nil ptr
	reader := bufio.NewReader(NewReader("current\n"))
	if err := ReadString(reader, "", nil, "", CurrentDirectoryOnEmpty); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// onEmpty error
	reader = bufio.NewReader(NewReader("\n"))
	throws := func(arg1 *string, arg2 string) error {
		return errors.Errorf("big-time error")
	}
	temp := ""
	ptr := &temp
	if err := ReadString(reader, "", ptr, "", throws); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "big-time error"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// reader error
	reader = bufio.NewReader(NewErrorReader("\n"))
	temp = ""
	ptr = &temp
	if err := ReadString(reader, "", ptr, "", throws); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "bad read"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}

	// input nil gets replaced
	reader = bufio.NewReader(NewReader("\n"))
	temp = ""
	ptr = &temp
	if err := ReadString(reader, "", ptr, "", CurrentDirectoryOnEmpty); err == nil {
		expected := "."
		if strings.Compare(*ptr, expected) != 0 {
			t.Errorf("data mismatch -- expected: `%s`, but got: `%s`",
				expected, *ptr)
		}
	} else {
		t.Errorf("ReadString error: %s", err)
	}

	// non empty input is kept
	reader = bufio.NewReader(NewReader("shake and bake\n"))
	temp = ""
	ptr = &temp
	if err := ReadString(reader, "", ptr, "", CurrentDirectoryOnEmpty); err == nil {
		expected := "shake and bake"
		if strings.Compare(*ptr, expected) != 0 {
			t.Errorf("data mismatch -- expected: `%s`, but got: `%s`",
				expected, *ptr)
		}
	} else {
		t.Errorf("ReadString error: %s", err)
	}
}

func Test_ReadString_retryOnEmpty(t *testing.T) {
	i := true
	f := ReadString
	temp := ""
	ptr := &temp
	reader := bufio.NewReader(NewReader("\n"))
	monkey.Patch(ReadString, func(r *bufio.Reader, p string, ptr *string, key string, v valid) error {
		if i {
			i = false
			return f(r, p, ptr, key, v)
		}
		temp = "hi there"
		return nil
	})

	if err := ReadString(reader, "", ptr, "common", RetryOnEmpty); err == nil {
		if i || temp != "hi there" {
			t.Errorf("failed to retry")
		}
	}
	monkey.Unpatch(ReadString)
}

func Test_ReadPassword_nilPtr(t *testing.T) {
	// nil ptr
	monkey.Patch(terminal.ReadPassword, func(i int) ([]uint8, error) {
		return ([]uint8)("current"), nil
	})
	if err := ReadPassword("", nil, "", FailOnEmpty); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}
	monkey.Unpatch(terminal.ReadPassword)
}

func Test_ReadPassword_onEmptyError(t *testing.T) {
	monkey.Patch(terminal.ReadPassword, func(i int) ([]uint8, error) {
		return ([]uint8)(""), nil
	})
	if err := ReadPassword("", nil, "", FailOnEmpty); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}
	monkey.Unpatch(terminal.ReadPassword)
}

func Test_ReadPassword_spacesIsStillEmpty(t *testing.T) {
	monkey.Patch(terminal.ReadPassword, func(i int) ([]uint8, error) {
		return ([]uint8)("   "), nil
	})
	if err := ReadPassword("", nil, "", FailOnEmpty); err == nil {
		t.Errorf("expected: `error`, but got: `nil`")
	} else {
		expected := "pointer cannot be nil"
		if !strings.HasPrefix(err.Error(), expected) {
			t.Errorf("error mismatch: expected: `%s`, but got: `%s`",
				expected, err.Error())
		}
	}
	monkey.Unpatch(terminal.ReadPassword)
}

func Test_ReadPassword_nilPtrOverwrittenByInput(t *testing.T) {
	// also tests trim space
	monkey.Patch(terminal.ReadPassword, func(i int) ([]uint8, error) {
		return ([]uint8)("shake and bake"), nil
	})
	temp := ""
	ptr := &temp
	if err := ReadPassword("", ptr, "common", FailOnEmpty); err == nil {
		expected := "shake and bake"
		if strings.Compare(*ptr, expected) != 0 {
			t.Errorf("data mismatch -- expected: `%s`, but got: `%s`",
				expected, *ptr)
		}
	} else {
		t.Errorf("ReadString error: %s", err)
	}
	monkey.Unpatch(terminal.ReadPassword)
}

func Test_ReadPassword_retryOnEmpty(t *testing.T) {
	i := true
	f := ReadPassword
	// also tests trim space
	monkey.Patch(terminal.ReadPassword, func(i int) ([]uint8, error) {
		return ([]uint8)(""), nil
	})
	monkey.Patch(ReadPassword, func(p string, ptr *string, key string, v valid) error {
		if i {
			i = false
			return f(p, ptr, key, v)
		}
		return nil
	})

	temp := ""
	ptr := &temp
	if err := ReadPassword("", ptr, "common", RetryOnEmpty); err == nil {
		if i {
			t.Errorf("failed to retry")
		}
	}
	monkey.Unpatch(terminal.ReadPassword)
	monkey.Unpatch(ReadPassword)
}
