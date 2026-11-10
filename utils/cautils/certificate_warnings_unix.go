//go:build unix

package cautils

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func writeCertificateWarning(w io.Writer, line string) {
	file, ok := w.(*os.File)
	if !ok {
		_, _ = io.WriteString(w, line)
		return
	}

	// os.File.Write raises SIGPIPE on stdout/stderr after EPIPE. Use the raw
	// connection instead so a failed warning cannot terminate issuance, without
	// changing the process-wide signal disposition or owning the descriptor.
	conn, err := file.SyscallConn()
	if err != nil {
		return
	}
	data := []byte(line)
	_ = conn.Write(func(fd uintptr) bool {
		for len(data) > 0 {
			n, err := unix.Write(int(fd), data)
			switch err {
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				return false
			}
			if err != nil || n == 0 {
				return true
			}
			data = data[n:]
		}
		return true
	})
}
