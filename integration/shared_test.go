package integration

import (
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/smallstep/cli/internal/cmd"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"step": cmd.Run, // main entrypoint name
	}))
}
