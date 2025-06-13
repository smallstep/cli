package integration

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestVersionCommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/version.txtar"},
	})
}

func TestBogusCommandFails(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/bogus.txtar"},
	})
}
