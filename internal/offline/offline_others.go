//go:build !js
// +build !js

package offline

import (
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func New(ctx *cli.Context, caConfig string) (CA, error) {
	return cautils.NewOfflineCA(ctx, caConfig)
}
