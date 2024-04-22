package certificate

import (
	"bytes"
	"encoding/json"
	"flag"
	"testing"

	"github.com/smallstep/assert"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"
)

var pemData = []byte(`-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIRAIPzjTtZi8QxcUTfxzLnmZEwDQYJKoZIhvcNAQELBQAw
FjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwNjEwMDEyMDA5WhcNMjAwNjEx
MDEyMDA5WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMn/S9bIdfObGlh7ed3RpDPJCZF9eaD2WcMrgovuHWsX
32UO1/pGoeklWhOnQQ+gYhflGrLZMMLqx6r+exVBuza7UYD3B5BUYdf7mbtYoGUq
4HbjGzI18Sd24OCsNiGRHkMxrDEcw+58CZ7AB65ypLdojsaS8DjguBmeD0rG0PtH
TQUN8A9VTS5XcI+UteZNwzJMNMXPZG9Z5xpSEPmqPKYcAR8f15O37EeTbn6ET87k
BYGrenT9Z4MhvWnss5tuF8i2OFOBLBUCpE0x6KtL4vRk+01e6Q/t88hrqcdnsntj
WFXpRyckzpRAlxepxOux75eblTyF6UmvCO0SzF0HbekCAwEAAaNoMGYwDgYDVR0P
AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4E
FgQUesmsNAakuLOoZXAjrLvVcxaSlzwwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20w
DQYJKoZIhvcNAQELBQADggEBALvpW/qWgxnxfcyrL92sbs6TCknDl7hpyityPByA
3VKpMdMbuuEseOsT42fLUm1RUR1unxffwERGNRtymug0kKn7kMIirFriSxUQVnIf
gpOSEGrPMKIVWKybzWNiLs9wEl45V6ySJ6xGVvXWqxG/0esFCC500KWrCTgCoyB+
DZhoSQOLyZyoeKc5xgbt42OS6wYawJ0e/3HoBLbR79iqamYhTraEacNdFcsdNaYj
4XBuJm5+CoJXmMATRZVo+h0pRZpr8W9XWdrRTKxNfnMz89yEj/ytGjqNISCvcigg
F5XY+AbpOho43YNC0yYrQj6xdGBareWHLkFCvSBEZ6bBW6E=
-----END CERTIFICATE-----
`)

func TestInspectCertificates(t *testing.T) {
	// This is just to get a simple CLI context
	app := &cli.App{}
	set := flag.NewFlagSet("contrive", 0)
	_ = set.String("format", "", "")
	ctx := cli.NewContext(app, set, nil)

	certs, err := pemutil.ParseCertificateBundle(pemData)
	assert.FatalError(t, err)

	type testCase struct {
		format string
		verify func(buf *bytes.Buffer)
	}

	tests := map[string]testCase{
		"format text": {"text",
			func(buf *bytes.Buffer) {
				assert.HasPrefix(t, buf.String(), "Certificate:")
			},
		},
		"format json": {"json",
			func(buf *bytes.Buffer) {
				var v interface{}
				err := json.Unmarshal(buf.Bytes(), &v)
				assert.NoError(t, err)
			},
		},
		"format pem": {"pem",
			func(buf *bytes.Buffer) {
				assert.Equals(t, string(pemData), buf.String())
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx.Set("format", tc.format)
			err := inspectCertificates(ctx, certs, &buf)
			assert.NoError(t, err)
			if err == nil {
				tc.verify(&buf)
			}
		})
	}

}

var csrPEMData = []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHmMIGNAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASGlyI2t5ibpcG+
hGm0JMW0or/QphyTlc4GGAccapsz4BeXkNucKpeX3nupFbbABHLcN/bjxL87Ims8
jz5sdl6xoCswKQYJKoZIhvcNAQkOMRwwGjAYBgNVHREEETAPggNmb2+CA2JhcoID
YmF6MAoGCCqGSM49BAMCA0gAMEUCIEuWM0UdEeDfvWqssxyoY4cUuv++FrmA97j+
Fbp7Kk6gAiEAuoyrBIvX28Spmeog9Jl4iBJYzceSNz8a7crRNGLTyjs=
-----END CERTIFICATE REQUEST-----
`)

func TestInspectCertificateRequest(t *testing.T) {
	// This is just to get a simple CLI context
	app := &cli.App{}
	set := flag.NewFlagSet("contrive", 0)
	_ = set.String("format", "", "")
	ctx := cli.NewContext(app, set, nil)

	csr, err := pemutil.ParseCertificateRequest(csrPEMData)
	assert.FatalError(t, err)

	type testCase struct {
		format string
		verify func(buf *bytes.Buffer)
	}

	tests := map[string]testCase{
		"format text": {"text",
			func(buf *bytes.Buffer) {
				assert.HasPrefix(t, buf.String(), "Certificate Request:")
			},
		},
		"format json": {"json",
			func(buf *bytes.Buffer) {
				var v interface{}
				err := json.Unmarshal(buf.Bytes(), &v)
				assert.NoError(t, err)
			},
		},
		"format pem": {"pem",
			func(buf *bytes.Buffer) {
				assert.Equals(t, string(csrPEMData), buf.String())
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx.Set("format", tc.format)
			err := inspectCertificateRequest(ctx, csr, &buf)
			assert.NoError(t, err)
			if err == nil {
				tc.verify(&buf)
			}
		})
	}

}
