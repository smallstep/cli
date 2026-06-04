package ssh

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxyDirectExitsWhenServerCloses verifies that proxyDirectWithIO returns
// promptly when the server closes the connection, even when stdin is still open.
//
// Without the fix, the two goroutines inside proxyDirectWithIO deadlock:
//
//  1. The server→stdout goroutine finishes (server closed the connection).
//  2. The stdin→server goroutine blocks on Read(os.Stdin) waiting for input
//     that never arrives, because the SSH client is itself waiting for the
//     ProxyCommand process to exit.
//  3. Neither side exits — the ProxyCommand hangs until an external timeout
//     (typically ~60 s on the client) kills it.
func TestProxyDirectExitsWhenServerCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// Server sends a message then closes the connection immediately.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("hello")) //nolint:errcheck
		conn.Close()
	}()

	// stdinR blocks on Read until stdinW is closed. We intentionally leave
	// stdinW open to simulate the client not having closed its stdin yet —
	// the normal case when sshd rejects a connection mid-session.
	stdinR, stdinW := io.Pipe()
	defer stdinW.Close()

	var stdout bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- proxyDirectWithIO("127.0.0.1", port, stdinR, &stdout)
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
		assert.Equal(t, "hello", stdout.String())
	case <-time.After(2 * time.Second):
		t.Fatal("proxyDirectWithIO did not exit after server closed the connection — stdin goroutine deadlock")
	}
}
