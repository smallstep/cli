package certificate

import (
	"errors"
	"fmt"
	"net"
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

func TestGetPeerCertificateServerName(t *testing.T) {
	host := "smallstep.com"
	serverName := host
	addrs, err := net.LookupIP(host)
	if err != nil {
		t.Fatalf("unknown host %s: %s", host, err)
	}
	addr := addrs[0].String()

	type newTest struct {
		addr, serverName string
		err              error
	}
	tests := map[string]newTest{
		"sni-disabled-host": {host, "", nil},
		"sni-enabled-host":  {host, serverName, nil},
		"sni-disabled-ip":   {addr, "", fmt.Errorf("failed to connect: x509: cannot validate certificate for %s because it doesn't contain any IP SANs", addr)},
		"sni-enabled-ip":    {addr, serverName, nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := getPeerCertificates(tc.addr, tc.serverName, "", false)
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
