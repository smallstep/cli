package certificate

import (
	"testing"

	"github.com/smallstep/assert"
)

func TestTrimUrlPrefix(t *testing.T) {
	type newTest struct {
		input, prefix, suffix string
		isURL                 bool
	}
	tests := map[string]newTest{
		"true-http":      {"https://smallstep.com", "https://", "smallstep.com", true},
		"true-tcp":       {"tcp://smallstep.com", "tcp://", "smallstep.com", true},
		"true-tls":       {"tls://smallstep.com", "tls://", "smallstep.com", true},
		"false":          {"./certs/root_ca.crt", "", "", false},
		"true-http-case": {"hTtPs://sMaLlStEp.cOm", "hTtPs://", "sMaLlStEp.cOm", true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			prefix, suffix, isURL := trimURLPrefix(tc.input)
			assert.Equals(t, tc.prefix, prefix)
			assert.Equals(t, tc.suffix, suffix)
			assert.Equals(t, tc.isURL, isURL)
		})
	}
}
