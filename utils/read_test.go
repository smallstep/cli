package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockReader struct {
	n   int
	err error
}

func (r *mockReader) Read([]byte) (int, error) {
	return r.n, r.err
}

// Helper function for setting os.Stdin for mocking in tests.
func setStdin(f *os.File) (cleanup func()) {
	old := stdin
	stdin = f
	return func() { stdin = old }
}

// Returns a temp file and a cleanup function to delete it.
func newFile(t *testing.T, data []byte) (file *os.File, cleanup func()) {
	f, err := os.CreateTemp(t.TempDir(), "utils-read-test")
	require.NoError(t, err)
	// write to temp file and reset read cursor to beginning of file
	_, err = f.Write(data)
	require.NoError(t, err)
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	return f, func() { os.Remove(f.Name()) }
}

func TestFileExists(t *testing.T) {
	content := []byte("my file content")
	f, cleanup := newFile(t, content)
	defer cleanup()

	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"ok", args{f.Name()}, true},
		{"nok", args{f.Name() + ".foo"}, false},
		{"empty", args{""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileExists(tt.args.path); got != tt.want {
				t.Errorf("FileExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadAll(t *testing.T) {
	content := []byte("read all this")

	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", args{bytes.NewReader(content)}, content, false},
		{"fail", args{&mockReader{err: fmt.Errorf("this is an error")}}, []byte{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadAll(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadAll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadString(t *testing.T) {
	c1 := []byte("read all this")
	c2 := []byte("read all this\n and all that")

	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{bytes.NewReader(c1)}, "read all this", false},
		{"ok with new line", args{bytes.NewReader(c2)}, "read all this", false},
		{"fail", args{&mockReader{err: fmt.Errorf("this is an error")}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadString(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	content := []byte("my file content")
	f, cleanup := newFile(t, content)
	defer cleanup()

	b, err := ReadFile(f.Name())
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, b), "expected %s to equal %s", b, content)
}

func TestReadFileStdin(t *testing.T) {
	content := []byte("my file content")
	mockStdin, cleanup := newFile(t, content)
	defer cleanup()
	defer setStdin(mockStdin)()

	b, err := ReadFile(stdinFilename)
	require.NoError(t, err)
	require.True(t, bytes.Equal(content, b), "expected %s to equal %s", b, content)
}

func TestReadPasswordFromFile(t *testing.T) {
	content := []byte("my-password-on-file\n")
	f, cleanup := newFile(t, content)
	defer cleanup()

	b, err := ReadPasswordFromFile(f.Name())
	require.NoError(t, err)
	require.True(t, bytes.Equal([]byte("my-password-on-file"), b), "expected %s to equal %s", b, content)
}

func TestStringReadPasswordFromFile(t *testing.T) {
	content := []byte("my-password-on-file\n")
	f, cleanup := newFile(t, content)
	defer cleanup()

	s, err := ReadStringPasswordFromFile(f.Name())
	require.NoError(t, err)
	require.Equal(t, "my-password-on-file", s, "expected %s to equal %s", s, content)
}

func TestReadInput(t *testing.T) {
	type args struct {
		prompt string
	}
	tests := []struct {
		name    string
		args    args
		before  func() func()
		want    []byte
		wantErr bool
	}{
		{"ok", args{"Write input"}, func() func() {
			content := []byte("my file content")
			mockStdin, cleanup := newFile(t, content)
			reset := setStdin(mockStdin)
			return func() {
				defer cleanup()
				reset()
			}
		}, []byte("my file content"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.before()
			defer cleanup()
			got, err := ReadInput(tt.args.prompt)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadInput() = %v, want %v", got, tt.want)
			}
		})
	}
}
