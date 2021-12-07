package keys

import (
	"io"
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// discard log output when testing
	log.SetOutput(io.Discard)

	result := m.Run()

	clean := func(files []string) {
		for _, f := range files {
			if _, err := os.Stat(f); !os.IsNotExist(err) {
				os.Remove(f)
			}
		}
	}
	clean([]string{"./test.key"})

	os.Exit(result)
}
