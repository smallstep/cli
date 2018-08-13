package errs

import (
	"io/ioutil"
	"os"
	"testing"

	"errors"

	"github.com/stretchr/testify/require"
)

func TestFileError(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{
			err:      os.NewSyscallError("open", errors.New("out of file descriptors")),
			expected: "open failed: out of file descriptors",
		},
		{
			err: func() error {
				_, err := ioutil.ReadFile("im-fairly-certain-this-file-doesnt-exist")
				require.Error(t, err)
				return err
			}(),
			expected: "open im-fairly-certain-this-file-doesnt-exist failed",
		},
		{
			err: func() error {
				err := os.Link("im-fairly-certain-this-file-doesnt-exist", "neither-does-this")
				require.Error(t, err)
				return err
			}(),
			expected: "link im-fairly-certain-this-file-doesnt-exist neither-does-this failed",
		},
	}
	for _, tt := range tests {
		err := FileError(tt.err, "myfile")
		require.Error(t, err)
		require.Contains(t, err.Error(), tt.expected)
	}
}
