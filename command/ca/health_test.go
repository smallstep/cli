package ca

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/certificates/authority/config"
	stepca "github.com/smallstep/certificates/ca"
)

// reservePort "reserves" a TCP port by opening a listener on a random
// port and immediately closing it. The port can then be assumed to be
// available for running a server on.
func reservePort(t *testing.T) (host, port string) {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	address := l.Addr().String()
	err = l.Close()
	require.NoError(t, err)

	host, port, err = net.SplitHostPort(address)
	require.NoError(t, err)

	return
}

func Test_healthAction(t *testing.T) {
	dir := t.TempDir()
	m, err := minica.New(minica.WithName("Step Integration"))
	require.NoError(t, err)

	rootFilepath := filepath.Join(dir, "root.crt")
	_, err = pemutil.Serialize(m.Root, pemutil.WithFilename(rootFilepath))
	require.NoError(t, err)

	intermediateCertFilepath := filepath.Join(dir, "intermediate.crt")
	_, err = pemutil.Serialize(m.Intermediate, pemutil.WithFilename(intermediateCertFilepath))
	require.NoError(t, err)

	intermediateKeyFilepath := filepath.Join(dir, "intermediate.key")
	_, err = pemutil.Serialize(m.Signer, pemutil.WithFilename(intermediateKeyFilepath))
	require.NoError(t, err)

	// get a random address to listen on and connect to; currently no nicer way to get one before starting the server
	// TODO(hs): find/implement a nicer way to expose the CA URL, similar to how e.g. httptest.Server exposes it?
	host, port := reservePort(t)

	cfg := &config.Config{
		Root:             []string{rootFilepath},
		IntermediateCert: intermediateCertFilepath,
		IntermediateKey:  intermediateKeyFilepath,
		Address:          net.JoinHostPort(host, port), // reuse the address that was just "reserved"
		DNSNames:         []string{"127.0.0.1", "[::1]", "localhost"},
		AuthorityConfig: &config.AuthConfig{
			AuthorityID:    "stepca-test",
			DeploymentType: "standalone-test",
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}
	c, err := stepca.New(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		err = c.Run()
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()

	caCommand := cli.Command{Name: "ca"}
	caCommand.Subcommands = []cli.Command{healthCommand()}

	app := cli.NewApp()
	app.Commands = cli.Commands{caCommand}
	err = app.Run([]string{"step", "ca", "health", "--root", rootFilepath, "--ca-url", fmt.Sprintf("https://localhost:%s", port)})
	assert.NoError(t, err)

	// done testing; stop and wait for the server to quit
	err = c.Stop()
	require.NoError(t, err)

	wg.Wait()
}
