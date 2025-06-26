package integration

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/smallstep/cli/internal/cmd"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"step": cmd.Run, // main entrypoint name
	})
}
