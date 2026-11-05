package cautils

import (
	"io"
	"strings"
	"unicode"

	"github.com/smallstep/certificates/cas/apiv1"
)

// PrintCertificateWarnings writes CA warnings as literal, single-line terminal
// data. A warning output failure never changes successful certificate issuance.
func PrintCertificateWarnings(w io.Writer, warnings []apiv1.CertificateWarning) {
	for _, warning := range warnings {
		message := sanitizeCertificateWarning(warning.Message)
		code := sanitizeCertificateWarning(warning.Code)
		if message == "" {
			if code == "" {
				message = "CA returned an unspecified warning"
			} else {
				message = "CA returned warning " + code
			}
		}
		if code != "" {
			message += " [" + code + "]"
		}
		// Do not cause callers to retry issuance if stderr is unavailable.
		writeCertificateWarning(w, "WARNING: "+message+"\n")
	}
}

func sanitizeCertificateWarning(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}
		return r
	}, text)
}
