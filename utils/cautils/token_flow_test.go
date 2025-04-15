package cautils

import (
	"flag"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/authority/provisioner"
)

func newContext(t *testing.T) *cli.Context {
	t.Helper()

	app := cli.NewApp()

	parentFlags := flag.NewFlagSet(fmt.Sprintf("parent-%s", t.Name()), 0)
	parentCtx := cli.NewContext(app, parentFlags, nil)

	set := flag.NewFlagSet(fmt.Sprintf("child-%s", t.Name()), 0)
	set.String("kid", "", "")
	set.String("admin-provisioner", "", "")
	set.String("provisioner", "", "")
	set.String("issuer", "", "")

	return cli.NewContext(app, set, parentCtx)
}

func TestProvisionerPromptPrompts(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		clictx := newContext(t)
		p := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p})
		require.NoError(t, err, "cannot create a new token: the CA does not have any provisioner configured")
		require.Same(t, p, got)
	})

	t.Run("select-kid-flag", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("kid", "client-id"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.NoError(t, err)
		require.Same(t, p1, got)
	})

	t.Run("select-admin-provisioner-flag", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("admin-provisioner", "oidc"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.NoError(t, err)
		require.Same(t, p1, got)

		clictx.Set("admin-provisioner", "scep")
		got, err = provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.NoError(t, err)
		require.Same(t, p2, got)
	})

	t.Run("select-provisioner-flag", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("provisioner", "oidc"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.NoError(t, err)
		require.Same(t, p1, got)

		clictx.Set("provisioner", "scep")
		got, err = provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.NoError(t, err)
		require.Same(t, p2, got)
	})

	t.Run("ignore-provisioner-flag", func(t *testing.T) {
		clictx := newContext(t) // provisioner flag is not set; in reality it'll be unset based on policy level

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.Error(t, err) // TODO(hs): would be nice to refactor to configurable output, and catch specific error cases (again)
		require.Nil(t, got)
	})

	t.Run("no-provisioners", func(t *testing.T) {
		clictx := newContext(t)

		got, err := provisionerPrompt(clictx, nil)
		require.EqualError(t, err, "cannot create a new token: the CA does not have any provisioner configured")
		require.Nil(t, got)
	})

	t.Run("select-kid-flag-non-existing", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("kid", "unknown-kid"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.EqualError(t, err, "invalid value 'unknown-kid' for flag '--kid'")
		require.Nil(t, got)
	})

	t.Run("select-admin-provisioner-flag-non-existing", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("admin-provisioner", "unknown"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.EqualError(t, err, "invalid value 'unknown' for flag '--admin-provisioner'")
		require.Nil(t, got)
	})

	t.Run("select-provisioner-flag-non-existing", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("provisioner", "unknown"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.EqualError(t, err, "invalid value 'unknown' for flag '--provisioner'")
		require.Nil(t, got)
	})

	t.Run("select-issuer-flag-non-existing", func(t *testing.T) {
		clictx := newContext(t)
		require.NoError(t, clictx.Set("issuer", "unknown"))

		p1 := &provisioner.OIDC{Name: "oidc", ClientID: "client-id"}
		p2 := &provisioner.SCEP{Name: "scep"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.EqualError(t, err, "invalid value 'unknown' for flag '--issuer'")
		require.Nil(t, got)
	})

	t.Run("multiple-select-ui", func(t *testing.T) {
		clictx := newContext(t)
		p1 := &provisioner.OIDC{Name: "oidc-1", ClientID: "client-id-1"}
		p2 := &provisioner.OIDC{Name: "oidc-2", ClientID: "client-id-1"}

		got, err := provisionerPrompt(clictx, []provisioner.Interface{p1, p2})
		require.Error(t, err) // TODO(hs): would be nice to refactor to configurable output, and catch specific error cases (again)
		require.Nil(t, got)
	})
}
