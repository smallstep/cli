package main

import (
	"bytes"
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smallstep/cli/internal/provisionerflag"
)

func TestAppHasAllCommands(t *testing.T) {
	app := newApp(&bytes.Buffer{}, &bytes.Buffer{})
	require.NotNil(t, app)

	require.Equal(t, "step", app.Name)
	require.Equal(t, "step", app.HelpName)

	var names = make([]string, 0, len(app.Commands))
	for _, c := range app.Commands {
		names = append(names, c.Name)
	}
	require.Equal(t, []string{
		"help", "api", "path", "base64", "fileserver",
		"certificate", "completion", "context", "crl",
		"crypto", "oauth", "version", "ca", "beta", "ssh",
	}, names)
}

const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"

var ansiRegex = regexp.MustCompile(ansi)

func TestAppRuns(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	app := newApp(stdout, stderr)
	require.NotNil(t, app)

	err := app.Run([]string{"step"})
	require.NoError(t, err)
	require.Empty(t, stderr.Bytes())

	output := ansiRegex.ReplaceAllString(stdout.String(), "")
	require.Contains(t, output, "step -- plumbing for distributed systems")
}

func TestAppHasSentinelFlagForIgnoringProvisionersFlag(t *testing.T) {
	app := newApp(nil, nil)
	require.NotNil(t, app)

	// this test only checks if the flag is present when an app is created
	// through [getApp]. This is sufficient for now to proof that the flag
	// exists in the actual released CLI binary.
	require.True(t, slices.ContainsFunc(app.Flags, func(f cli.Flag) bool {
		return f.GetName() == provisionerflag.DisabledSentinelFlagName()
	}))
}
