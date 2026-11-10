package cautils

import (
	"bytes"
	"errors"
	"testing"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/require"
)

func TestCertificateWarnings(t *testing.T) {
	t.Run("ordered literal terminal data", func(t *testing.T) {
		var output bytes.Buffer
		PrintCertificateWarnings(&output, []apiv1.CertificateWarning{
			{Message: "first\n\r\t\x1b[31m\x00\x7f\u0085\u009b\u2028\u2029\u202e\u200d café", Code: "future\n\x1b\u2028\u202e"},
			{Message: `{{ "literal" | red }} %s`, Code: "unknown_code"},
			{Message: "message only"},
		})
		require.Equal(t, "WARNING: first    [31m         café [future    ]\n"+
			"WARNING: {{ \"literal\" | red }} %s [unknown_code]\n"+
			"WARNING: message only\n", output.String())
	})

	t.Run("empty fields have useful fallbacks", func(t *testing.T) {
		var output bytes.Buffer
		PrintCertificateWarnings(&output, []apiv1.CertificateWarning{
			{Code: "future_code"},
			{},
		})
		require.Equal(t, "WARNING: CA returned warning future_code [future_code]\n"+
			"WARNING: CA returned an unspecified warning\n", output.String())
	})

	t.Run("warning free responses are silent", func(t *testing.T) {
		var output bytes.Buffer
		PrintCertificateWarnings(&output, nil)
		PrintCertificateWarnings(&output, []apiv1.CertificateWarning{})
		require.Empty(t, output.String())
	})

	t.Run("writer failures do not stop later warnings", func(t *testing.T) {
		writer := &failingCertificateWarningWriter{}
		PrintCertificateWarnings(writer, []apiv1.CertificateWarning{
			{Message: "first"},
			{Message: "second"},
		})
		require.Equal(t, []string{"WARNING: first\n", "WARNING: second\n"}, writer.attempts)
	})
}

type failingCertificateWarningWriter struct {
	attempts []string
}

func (w *failingCertificateWarningWriter) Write(p []byte) (int, error) {
	w.attempts = append(w.attempts, string(p))
	return 0, errors.New("stderr unavailable")
}
