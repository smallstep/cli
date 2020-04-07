// +build integration

package integration

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
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

func TestVersion(t *testing.T) {
	out, err := Output("step version | head -1")
	assert.FatalError(t, err)
	assert.True(t, strings.HasPrefix(string(out), "Smallstep CLI"))
}

func TestCryptoJWTSign(t *testing.T) {
	out, err := Output("step crypto jwt sign -key testdata/p256.pem -iss TestIssuer -aud TestAudience -sub TestSubject -nbf 1 -iat 1 -exp 1 -subtle")
	assert.FatalError(t, err)
	assert.True(t, strings.HasPrefix(string(out), "eyJhbGciOiJFUzI1NiIsImtpZCI6IiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUZXN0QXVkaWVuY2UiLCJleHAiOjEsImlhdCI6MSwiaXNzIjoiVGVzdElzc3VlciIsIm5iZiI6MSwic3ViIjoiVGVzdFN1YmplY3QifQ."))
}

func TestCryptoJWTVerifyWithPrivate(t *testing.T) {
	exp := time.Now().Add(1 * time.Minute)
	out, err := CombinedOutput(fmt.Sprintf("step crypto jwt sign -key testdata/p256.pem -iss TestIssuer -aud TestAudience -sub TestSubject -exp %d | step crypto jwt verify -key testdata/p256.pem -subtle", exp.Unix()))
	assert.FatalError(t, err)
	m := make(map[string]interface{})
	assert.FatalError(t, json.Unmarshal(out, &m))
	assert.Equals(t, "TestIssuer", m["payload"].(map[string]interface{})["iss"])
}

func TestCertificateFingerprint(t *testing.T) {
	tests := []struct {
		name string
		crt  string
		flag string
		want string
	}{
		{"default", "test_files/intermediate_ca.crt", "", "626dca961bfde13341b32e7711c7127612988dbc5d0082fb220efd8ab4087b4b"},
		{"hex", "test_files/intermediate_ca.crt", " --format=hex", "626dca961bfde13341b32e7711c7127612988dbc5d0082fb220efd8ab4087b4b"},
		{"base64", "test_files/intermediate_ca.crt", " --format=base64", "Ym3Klhv94TNBsy53EccSdhKYjbxdAIL7Ig79irQIe0s="},
		{"base64url", "test_files/intermediate_ca.crt", " --format=base64-url", "Ym3Klhv94TNBsy53EccSdhKYjbxdAIL7Ig79irQIe0s="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Output(fmt.Sprintf("step certificate fingerprint %s%s", tt.crt, tt.flag))
			assert.FatalError(t, err)
			assert.True(t, strings.HasPrefix(string(out), tt.want))
		})
	}
}
