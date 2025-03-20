// this package is used for ignoring the provisioner flag in specific
// cli commands.
package provisionerflag_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	"github.com/smallstep/cli/internal/provisionerflag"
)

func TestProvisionerFlagCanBeIgnored(t *testing.T) {
	t.Parallel()

	app := cli.NewApp()

	t.Run("not-ignored", func(t *testing.T) {
		t.Parallel()

		parentFlags := flag.NewFlagSet("parent", 0)
		parentFlags.String(provisionerflag.DisabledSentinelFlagName(), "", "")

		parent := cli.NewContext(app, parentFlags, nil)
		ctx := cli.NewContext(app, flag.NewFlagSet("test", 0), parent)

		require.False(t, provisionerflag.ShouldBeIgnored(ctx))
	})

	t.Run("child", func(t *testing.T) {
		t.Parallel()

		parent := cli.NewContext(app, flag.NewFlagSet("parent", 0), nil)

		childFlags := flag.NewFlagSet("test", 0)
		childFlags.String(provisionerflag.DisabledSentinelFlagName(), "", "")
		ctx := cli.NewContext(app, childFlags, parent)

		provisionerflag.Ignore(ctx)

		require.True(t, provisionerflag.ShouldBeIgnored(ctx))
	})

	t.Run("parent", func(t *testing.T) {
		t.Parallel()

		parentFlags := flag.NewFlagSet("parent", 0)
		parentFlags.String(provisionerflag.DisabledSentinelFlagName(), "", "")

		parent := cli.NewContext(app, parentFlags, nil)
		ctx := cli.NewContext(app, flag.NewFlagSet("test", 0), parent)

		provisionerflag.Ignore(ctx)

		require.True(t, provisionerflag.ShouldBeIgnored(ctx))
	})

	t.Run("chain", func(t *testing.T) {
		t.Parallel()

		parentFlags := flag.NewFlagSet("parent", 0)
		parentFlags.String(provisionerflag.DisabledSentinelFlagName(), "", "")

		parent := cli.NewContext(app, parentFlags, nil)
		ctx := cli.NewContext(app, flag.NewFlagSet("test-1", 0), parent)
		ctx = cli.NewContext(app, flag.NewFlagSet("test-2", 0), ctx)
		ctx = cli.NewContext(app, flag.NewFlagSet("test-3", 0), ctx)

		provisionerflag.Ignore(ctx)

		require.True(t, provisionerflag.ShouldBeIgnored(ctx))
	})

	t.Run("nil-context", func(t *testing.T) {
		t.Parallel()

		require.Panics(t, func() { provisionerflag.Ignore(nil) })
	})

	t.Run("flag-undefined", func(t *testing.T) {
		t.Parallel()

		parent := cli.NewContext(app, flag.NewFlagSet("parent", 0), nil)
		ctx := cli.NewContext(app, flag.NewFlagSet("test", 0), parent)

		require.Panics(t, func() { provisionerflag.Ignore(ctx) })
	})
}
