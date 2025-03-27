package main

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
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
