package certificate

import (
	"errors"
	"net"
	"testing"

	"github.com/smallstep/assert"
)

func TestGetPeerCertificateServerName(t *testing.T) {
	host := "smallstep.com"
	serverName := host
	ips, err := net.LookupIP(host)
	if err != nil {
		t.Fatalf("unknown host %s: %s", host, err)
	}
	var addr string
	for i, ip := range ips {
		if ip.To4() != nil {
			addr = ips[i].String()
			break
		}
	}
	if addr == "" {
		assert.FatalError(t, errors.New("could not find ipv4 address for smallstep.com"))
		return
	}

	type newTest struct {
		addr, serverName string
		err              error
	}
	tests := map[string]newTest{
		"sni-disabled-host": {host, "", nil},
		"sni-enabled-host":  {host, serverName, nil},
		"sni-disabled-ip":   {addr, "", errors.New("failed to connect")},
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
