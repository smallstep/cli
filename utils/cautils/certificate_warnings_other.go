//go:build !unix

package cautils

import "io"

func writeCertificateWarning(w io.Writer, line string) {
	_, _ = io.WriteString(w, line)
}
