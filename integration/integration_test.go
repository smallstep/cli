//go:build integration
// +build integration

package integration

import (
	"flag"
	"log"
	"os"
	"testing"
	"time"
)

const (
	TempDirectory  = "testdata-tmp"
	DefaultTimeout = 2 * time.Second
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Setenv("PATH", os.Getenv("GOPATH")+"/src/github.com/smallstep/cli/bin"+":"+os.Getenv("PATH"))
	if err := os.Mkdir(TempDirectory, os.ModeDir|os.ModePerm); err != nil {
		log.Fatal(err)
	}
	var rval int
	defer func() {
		if os.Getenv("STEP_INTEGRATION_DEBUG") != "1" {
			os.RemoveAll(TempDirectory)
		}
		if err := recover(); err != nil {
			log.Fatal(err)
		}
		os.Exit(rval)
	}()
	rval = m.Run()
}
