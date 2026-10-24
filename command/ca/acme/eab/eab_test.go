package eab

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smallstep/linkedca"
)

func TestToCLI(t *testing.T) {
	created := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	bound := time.Date(2026, 7, 6, 13, 30, 0, 0, time.UTC)

	t.Run("bound key", func(t *testing.T) {
		eak := &linkedca.EABKey{
			Id:          "keyid",
			Provisioner: "my_acme",
			Reference:   "my_ref",
			HmacKey:     []byte("secret-hmac-key"),
			Account:     "acct-1",
			CreatedAt:   timestamppb.New(created),
			BoundAt:     timestamppb.New(bound),
		}

		got := toCLI(nil, nil, eak)
		assert.Equal(t, "keyid", got.ID)
		assert.Equal(t, "my_acme", got.Provisioner)
		assert.Equal(t, "my_ref", got.Reference)
		assert.Equal(t, "c2VjcmV0LWhtYWMta2V5", got.Key) // base64 raw-url of the hmac key
		assert.Equal(t, "acct-1", got.Account)
		assert.Equal(t, "2026-07-06 12:00:00 +00:00", got.CreatedAt)
		assert.Equal(t, "2026-07-06 13:30:00 +00:00", got.BoundAt)
	})

	t.Run("unbound key with zero timestamps", func(t *testing.T) {
		eak := &linkedca.EABKey{
			Id:          "keyid",
			Provisioner: "my_acme",
			CreatedAt:   timestamppb.New(time.Time{}),
			BoundAt:     timestamppb.New(time.Time{}),
		}

		got := toCLI(nil, nil, eak)
		// zero timestamps are represented as empty strings so they are dropped
		// from JSON via omitempty.
		assert.Empty(t, got.CreatedAt)
		assert.Empty(t, got.BoundAt)
		assert.Empty(t, got.Account)
	})
}

func TestCLIEAK_JSON(t *testing.T) {
	t.Run("add output includes key and omits empty fields", func(t *testing.T) {
		eak := &cliEAK{
			ID:          "keyid",
			Provisioner: "my_acme",
			Reference:   "my_ref",
			Key:         "c2VjcmV0",
		}

		b, err := json.Marshal(eak)
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Equal(t, "keyid", m["id"])
		assert.Equal(t, "my_acme", m["provisioner"])
		assert.Equal(t, "my_ref", m["reference"])
		assert.Equal(t, "c2VjcmV0", m["key"])
		assert.NotContains(t, m, "createdAt")
		assert.NotContains(t, m, "boundAt")
		assert.NotContains(t, m, "account")
	})

	t.Run("list output omits the secret key", func(t *testing.T) {
		eak := &cliEAK{
			ID:          "keyid",
			Provisioner: "my_acme",
			Reference:   "my_ref",
			Key:         "", // cleared for list output
			CreatedAt:   "2026-07-06 12:00:00 +00:00",
			Account:     "acct-1",
		}

		b, err := json.Marshal(eak)
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		assert.NotContains(t, m, "key")
		assert.Equal(t, "2026-07-06 12:00:00 +00:00", m["createdAt"])
		assert.Equal(t, "acct-1", m["account"])
		assert.NotContains(t, m, "boundAt")
	})
}
