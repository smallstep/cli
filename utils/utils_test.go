package utils

import (
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func assertHasPrefix(t *testing.T, s, p string) bool {
	if strings.HasPrefix(s, p) {
		return true
	}
	t.Helper()
	t.Errorf("%q is not a prefix of %q", p, s)
	return false
}

func TestTrimURL(t *testing.T) {
	type newTest struct {
		input, host string
		isURL       bool
		err         error
	}
	tests := map[string]newTest{
		"true-http":      {"https://smallstep.com", "smallstep.com:443", true, nil},
		"true-tcp":       {"tcp://smallstep.com:8080", "smallstep.com:8080", true, nil},
		"true-tls":       {"tls://smallstep.com/onboarding", "smallstep.com:443", true, nil},
		"false":          {"./certs/root_ca.crt", "", false, nil},
		"false-err":      {"https://google.com hello", "", false, errors.New(`error parsing "https://google.com hello"`)},
		"true-http-case": {"hTtPs://sMaLlStEp.cOm", "sMaLlStEp.cOm:443", true, nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			host, isURL, err := TrimURL(tc.input)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.isURL, isURL)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assertHasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
