package sshutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_newOptions(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		o := newOptions(nil)
		require.False(t, o.confirmBeforeUse)
		require.Nil(t, o.filterBySignatureKey)
		require.Nil(t, o.removeExpiredKey)
	})

	t.Run("confirmBeforeUse", func(t *testing.T) {
		o := newOptions([]AgentOption{WithConfirmBeforeUse()})
		require.True(t, o.confirmBeforeUse)
	})
}
