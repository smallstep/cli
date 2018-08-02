package x509util

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// discard log output when testing
	log.SetOutput(ioutil.Discard)

	result := m.Run()

	clean := func(files []string) {
		for _, f := range files {
			if _, err := os.Stat(f); !os.IsNotExist(err) {
				os.Remove(f)
			}
		}
	}
	clean([]string{"./test.crt"})

	os.Exit(result)
}
