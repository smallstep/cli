// this package is used for ignoring the provisioner flag in specific
// cli commands.
package provisionerflag

import (
	"github.com/urfave/cli"
)

var disabledSentinel = "/x-disable-provisioner-flag"

// DisabledSentinelFlagName returns the name of the sentinel flag
// that can be used to ignore the provisioner flag in specific cli commands.
func DisabledSentinelFlagName() string {
	return disabledSentinel
}

// DisabledSentinelFlag is a sentinel flag that can be used to ignore
// the provisioner flag in specific cli commands.
var DisabledSentinelFlag = cli.BoolFlag{
	Name:   disabledSentinel,
	Hidden: true,
}

// Ignore marks the provisioner flag to be ignored. If an error occurs it
// will traverse the [cli.Context] recursively until setting the value
// succeeds or the root context is reached. If the value is not set along
// the way, it will panic.
func Ignore(ctx *cli.Context) {
	if ctx == nil {
		panic("context is nil")
	}

	err := ctx.Set(disabledSentinel, "true")
	switch {
	case err == nil:
		return
	case ctx.Parent() != nil:
		Ignore(ctx.Parent())
	default:
		panic(err)
	}
}

// ShouldBeIgnored returns whether the provisioner flag should be ignored.
// If the [cli.Context] does not contain the sentinel flag value, it will
// recursively look for it up to the root context.
func ShouldBeIgnored(ctx *cli.Context) bool {
	if ctx.IsSet(disabledSentinel) && ctx.String(disabledSentinel) == "true" {
		return true
	}

	// recursively look for the sentinel value in the parent context
	if ctx.Parent() != nil {
		return ShouldBeIgnored(ctx.Parent())
	}

	return false
}
