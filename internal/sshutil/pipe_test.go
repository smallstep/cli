package sshutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeterminesWindowsPipeName(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		assert.Equal(t, `\\.\\pipe\\openssh-ssh-agent`, determineWindowsPipeName())
	})

	t.Run("valid-config-file", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "Users", "username", ".ssh", "config")

		t.Setenv("HOMEDRIVE", dir)
		t.Setenv("HOMEPATH", filepath.Join("Users", "username"))
		err := os.MkdirAll(filepath.Dir(file), 0777)
		require.NoError(t, err)

		err = os.WriteFile(file, []byte(`IdentityAgent \\.\\pipe\\pageant.user.abcd`), 0600)
		require.NoError(t, err)

		assert.Equal(t, `\\.\\pipe\\pageant.user.abcd`, determineWindowsPipeName())
	})

	t.Run("invalid-config-file", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "Users", "username", ".ssh", "config")

		t.Setenv("HOMEDRIVE", dir)
		t.Setenv("HOMEPATH", filepath.Join("Users", "username"))
		err := os.MkdirAll(filepath.Dir(file), 0777)
		require.NoError(t, err)
		err = os.WriteFile(file, []byte(`NoIdentityAgent \\.\\pipe\\pageant.user.abcd`), 0600)
		require.NoError(t, err)

		assert.Equal(t, `\\.\\pipe\\openssh-ssh-agent`, determineWindowsPipeName())
	})
}

func TestReadsWindowsPipeNameFromFile(t *testing.T) {
	t.Run("empty-path", func(t *testing.T) {
		assert.Equal(t, ``, readWindowsPipeNameFrom(""))
	})

	t.Run("valid-config-file", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "config")

		err := os.WriteFile(file, []byte(`IdentityAgent \\.\\pipe\\pageant.user.abcd`), 0600)
		require.NoError(t, err)

		assert.Equal(t, `\\.\\pipe\\pageant.user.abcd`, readWindowsPipeNameFrom(file))
	})

	t.Run("invalid-config-file", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "config")

		err := os.WriteFile(file, []byte(`NoIdentityAgent \\.\\pipe\\pageant.user.abcd`), 0600)
		require.NoError(t, err)

		assert.Equal(t, ``, readWindowsPipeNameFrom(file))
	})
}
