package script

import (
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/smallstep/cli/internal/cmd"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"step": cmd.Run,
	}))
}

func TestHelp(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/help.txtar"},
	})
}

func TestCryptoHelp(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/crypto/help.txtar"},
	})
}

func TestBogusCommand(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/bogus.txtar"},
	})
}
