package certificate

import (
	"errors"
	"testing"

	"github.com/smallstep/assert"
)

func TestTrimURL(t *testing.T) {
	type newTest struct {
		input, host string
		isURL       bool
		err         error
	}
	tests := map[string]newTest{
		"true-http":      {"https://smallstep.com", "smallstep.com", true, nil},
		"true-tcp":       {"tcp://smallstep.com:8080", "smallstep.com:8080", true, nil},
		"true-tls":       {"tls://smallstep.com/onboarding", "smallstep.com", true, nil},
		"false":          {"./certs/root_ca.crt", "", false, nil},
		"false-err":      {"https://google.com hello", "", false, errors.New("error parsing URL 'https://google.com hello'")},
		"true-http-case": {"hTtPs://sMaLlStEp.cOm", "sMaLlStEp.cOm", true, nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			host, isURL, err := trimURL(tc.input)
			assert.Equals(t, tc.host, host)
			assert.Equals(t, tc.isURL, isURL)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
