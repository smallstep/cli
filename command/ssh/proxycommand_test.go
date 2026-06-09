package ssh

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test_proxyDirectWithIO_serverClosesBeforeStdin reproduces smallstep/cli#1641:
// when the server closes the connection before the client has closed stdin, the
// proxycommand must still return promptly. Previously it would block in
// wg.Wait() forever because the stdin->conn goroutine stayed blocked reading a
// stdin that never reaches EOF (the ssh client keeps it open until the
// proxycommand exits).
func Test_proxyDirectWithIO_serverClosesBeforeStdin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	// Server sends some data and immediately closes the connection.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// stdin that never reaches EOF, simulating the ssh client keeping the
	// proxycommand's stdin open for the lifetime of the session.
	stdinR, stdinW := io.Pipe()
	defer stdinW.Close() // write end intentionally left open during the call

	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- proxyDirectWithIO(host, port, stdinR, &stdout)
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
		require.Equal(t, "hello", stdout.String())
	case <-time.After(5 * time.Second):
		t.Fatal("proxyDirectWithIO did not return after the server closed the connection")
	}
}
