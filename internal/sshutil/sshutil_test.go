package sshutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/keyutil"
)

func Test_parseECDSA(t *testing.T) {
	t.Run("p256", func(t *testing.T) {
		k, err := keyutil.GenerateKey("EC", "P-256", 0)
		require.NoError(t, err)

		ek := k.(*ecdsa.PrivateKey)
		pub, err := ssh.NewPublicKey(ek.Public())
		require.NoError(t, err)
		require.Equal(t, "ecdsa-sha2-nistp256", pub.Type())

		got, err := parseECDSA(pub.Marshal())
		require.NoError(t, err)

		require.Equal(t, elliptic.P256(), got.Curve)
		require.True(t, got.Equal(ek.Public()))
	})

	t.Run("p384", func(t *testing.T) {
		k, err := keyutil.GenerateKey("EC", "P-384", 0)
		require.NoError(t, err)

		ek := k.(*ecdsa.PrivateKey)
		pub, err := ssh.NewPublicKey(ek.Public())
		require.NoError(t, err)
		require.Equal(t, "ecdsa-sha2-nistp384", pub.Type())

		got, err := parseECDSA(pub.Marshal())
		require.NoError(t, err)

		require.Equal(t, elliptic.P384(), got.Curve)
		require.True(t, got.Equal(ek.Public()))
	})

	t.Run("p521", func(t *testing.T) {
		k, err := keyutil.GenerateKey("EC", "P-521", 0)
		require.NoError(t, err)

		ek := k.(*ecdsa.PrivateKey)
		pub, err := ssh.NewPublicKey(ek.Public())
		require.NoError(t, err)
		require.Equal(t, "ecdsa-sha2-nistp521", pub.Type())

		got, err := parseECDSA(pub.Marshal())
		require.NoError(t, err)

		require.Equal(t, elliptic.P521(), got.Curve)
		require.True(t, got.Equal(ek.Public()))
	})

	t.Run("unmarshal-error", func(t *testing.T) {
		k, err := keyutil.GenerateKey("EC", "P-256", 0)
		require.NoError(t, err)

		ek := k.(*ecdsa.PrivateKey)
		pub, err := ssh.NewPublicKey(ek.Public())
		require.NoError(t, err)
		require.Equal(t, "ecdsa-sha2-nistp256", pub.Type())

		b := pub.Marshal()
		b = b[:len(b)-10] // shorter than expected key

		got, err := parseECDSA(b)
		require.Error(t, err)
		require.EqualError(t, err, "error unmarshaling public key: ssh: short read")
		require.Nil(t, got)
	})

	t.Run("invalid-curve", func(t *testing.T) {
		k, err := keyutil.GenerateKey("EC", "P-256", 0)
		require.NoError(t, err)

		ek := k.(*ecdsa.PrivateKey)
		pub, err := ssh.NewPublicKey(ek.Public())
		require.NoError(t, err)
		require.Equal(t, "ecdsa-sha2-nistp256", pub.Type())

		b := pub.Marshal()
		b = bytes.ReplaceAll(b, []byte("nistp256"), []byte("nistp255")) // set unknown curve

		got, err := parseECDSA(b)
		require.Error(t, err)
		require.EqualError(t, err, "unsupported curve nistp255")
		require.Nil(t, got)
	})

	t.Run("invalid-key", func(t *testing.T) {
		k, err := keyutil.GenerateKey("EC", "P-256", 0)
		require.NoError(t, err)

		ek := k.(*ecdsa.PrivateKey)
		pub, err := ssh.NewPublicKey(ek.Public())
		require.NoError(t, err)
		require.Equal(t, "ecdsa-sha2-nistp256", pub.Type())

		b := pub.Marshal()
		start, end := len(b)-65, len(b)
		zeroes := make([]byte, end-start)
		copy(b[start:end], zeroes) // zeroize the key

		got, err := parseECDSA(b)
		require.Error(t, err)
		require.EqualError(t, err, "failed to create key: crypto/ecdh: invalid public key")
		require.Nil(t, got)
	})
}
