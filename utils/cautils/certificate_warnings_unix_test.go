//go:build unix

package cautils

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/stretchr/testify/require"
)

func TestCertificateWarningsBrokenStderr(t *testing.T) {
	if os.Getenv("STEP_TEST_WARNING_BROKEN_STDERR") == "1" {
		PrintCertificateWarnings(os.Stderr, []apiv1.CertificateWarning{{Message: "shortened validity"}})
		fmt.Println("credential handling continued")
		os.Exit(0)
	}

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	t.Cleanup(func() { writer.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertificateWarningsBrokenStderr$")
	cmd.Env = append(os.Environ(), "STEP_TEST_WARNING_BROKEN_STDERR=1")
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, writer
	require.NoError(t, cmd.Run())
	require.Equal(t, "credential handling continued\n", stdout.String())
}
