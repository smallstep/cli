package certificate

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"strings"
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

func TestInspectCertificates_Logotypes(t *testing.T) {
	mustMarshal := func(val interface{}) []byte {
		b, err := asn1.Marshal(val)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	wrapExplicit := func(tag int, payload []byte) []byte {
		var lenBytes []byte
		length := len(payload)
		if length < 128 {
			lenBytes = []byte{byte(length)}
		} else if length < 256 {
			lenBytes = []byte{0x81, byte(length)}
		} else {
			lenBytes = []byte{0x82, byte(length >> 8), byte(length & 0xff)}
		}
		result := []byte{byte(0xa0 | tag)}
		result = append(result, lenBytes...)
		result = append(result, payload...)
		return result
	}

	wrapSequence := func(payload []byte) []byte {
		var lenBytes []byte
		length := len(payload)
		if length < 128 {
			lenBytes = []byte{byte(length)}
		} else if length < 256 {
			lenBytes = []byte{0x81, byte(length)}
		} else {
			lenBytes = []byte{0x82, byte(length >> 8), byte(length & 0xff)}
		}
		result := []byte{0x30}
		result = append(result, lenBytes...)
		result = append(result, payload...)
		return result
	}

	// Direct CHOICE value [0] LogotypeData
	directDataBytes := mustMarshal(LogotypeData{
		Image: []LogotypeImage{
			{
				ImageDetails: LogotypeDetails{
					MediaType:   "image/png",
					LogotypeURI: []string{"https://example.com/subject-direct.png"},
				},
			},
		},
	})
	directDataBytes[0] = 0xa0 // choice tag [0] implicit

	// Indirect CHOICE value [1] LogotypeReference
	indirectRefBytes := mustMarshal(LogotypeReference{
		RefStructURI: []string{"https://example.com/issuer-indirect.png"},
	})
	indirectRefBytes[0] = 0xa1 // choice tag [1] implicit

	// Community LOGOS list element (direct Choice [0] LogotypeData)
	communityDirectBytes := mustMarshal(LogotypeData{
		Image: []LogotypeImage{
			{
				ImageDetails: LogotypeDetails{
					MediaType:   "image/svg+xml",
					LogotypeURI: []string{"https://example.com/community-direct.svg"},
				},
			},
		},
	})
	communityDirectBytes[0] = 0xa0

	// Community LOGOS list element (indirect Choice [1] LogotypeReference)
	communityIndirectBytes := mustMarshal(LogotypeReference{
		RefStructURI: []string{"https://example.com/community-indirect.png"},
	})
	communityIndirectBytes[0] = 0xa1

	// OtherLogotypeInfo element
	otherInfoBytes := mustMarshal(OtherLogotypeInfo{
		LogotypeType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12, 99},
		Info: asn1.RawValue{
			FullBytes: communityDirectBytes,
		},
	})

	// Wrap in communityLogos explicit tag [0]
	communitySeqBytes := append(communityDirectBytes, communityIndirectBytes...)
	communityLogosDER := wrapExplicit(0, wrapSequence(communitySeqBytes))

	// Wrap in issuerLogo explicit tag [1]
	issuerLogoDER := wrapExplicit(1, indirectRefBytes)

	// Wrap in subjectLogo explicit tag [2]
	subjectLogoDER := wrapExplicit(2, directDataBytes)

	// Wrap in otherLogos explicit tag [3]
	otherLogosDER := wrapExplicit(3, wrapSequence(otherInfoBytes))

	var extnBytes []byte
	extnBytes = append(extnBytes, communityLogosDER...)
	extnBytes = append(extnBytes, issuerLogoDER...)
	extnBytes = append(extnBytes, subjectLogoDER...)
	extnBytes = append(extnBytes, otherLogosDER...)

	extDER := wrapSequence(extnBytes)

	certs, err := pemutil.ParseCertificateBundle(pemData)
	if err != nil {
		t.Fatal(err)
	}
	crt := certs[0]
	crt.Extensions = append(crt.Extensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12},
		Value: extDER,
	})

	app := &cli.App{}
	set := flag.NewFlagSet("contrive", 0)
	_ = set.String("format", "text", "")
	ctx := cli.NewContext(app, set, nil)

	var buf bytes.Buffer
	err = inspectCertificates(ctx, []*x509.Certificate{crt}, &buf)
	assert.NoError(t, err)

	output := buf.String()
	t.Logf("Output:\n%s", output)

	if !strings.Contains(output, "Logotype URI: https://example.com/community-direct.svg") {
		t.Error("missing community-direct URI")
	}
	if !strings.Contains(output, "Logotype URI: https://example.com/community-indirect.png") {
		t.Error("missing community-indirect URI")
	}
	if !strings.Contains(output, "Logotype URI: https://example.com/issuer-indirect.png") {
		t.Error("missing issuer-indirect URI")
	}
	if !strings.Contains(output, "Logotype URI: https://example.com/subject-direct.png") {
		t.Error("missing subject-direct URI")
	}
}

