package utils

import (
	"os"

	"github.com/smallstep/cli-utils/errs"
)

// File represents a wrapper on os.File that supports read, write, seek and
// close methods, but they won't be called if an error occurred before.
type File struct {
	File *os.File
	err  error
}

// OpenFile calls os.OpenFile method and returns the os.File wrapped.
func OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, errs.FileError(err, name)
	}
	return &File{
		File: f,
	}, nil
}

// error writes f.err if it's not set and returns f.err.
func (f *File) error(err error) error {
	if f.err == nil && err != nil {
		f.err = errs.FileError(err, f.File.Name())
	}
	return f.err
}

// Close wraps `func (*os.File) Close` it will always call Close but the error
// return will be the first error thrown if any.
func (f *File) Close() error {
	return f.error(f.File.Close())
}

// Read wraps `func (*os.File) Read` but doesn't perform the operation if a
// previous error was thrown.
func (f *File) Read(b []byte) (n int, err error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err = f.File.Read(b)
	return n, f.error(err)
}

// ReadAt wraps `func (*os.File) ReadAt` but doesn't perform the operation if a
// previous error was thrown.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err = f.File.ReadAt(b, off)
	return n, f.error(err)
}

// Seek wraps `func (*os.File) Seek` but doesn't perform the operation if a
// previous error was thrown.
func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	if f.err != nil {
		return 0, f.err
	}
	ret, err = f.File.Seek(offset, whence)
	return ret, f.error(err)
}

// Write wraps `func (*os.File) Write` but doesn't perform the operation if a
// previous error was thrown.
func (f *File) Write(b []byte) (n int, err error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err = f.File.Write(b)
	return n, f.error(err)
}

// WriteAt wraps `func (*os.File) WriteAt` but doesn't perform the operation if
// a previous error was thrown.
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err = f.File.WriteAt(b, off)
	return n, f.error(err)
}

// WriteString wraps `func (*os.File) WriteString` but doesn't perform the
// operation if a previous error was thrown.
func (f *File) WriteString(s string) (n int, err error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err = f.File.WriteString(s)
	return n, f.error(err)
}
