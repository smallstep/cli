package jose

import (
	"crypto/sha1"
	"encoding/base64"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
)

var (
	badCertFile     = "./testdata/bad-rsa.crt"
	badKeyFile      = "./testdata/bad-rsa.key"
	invalidCertFile = "./testdata/invalid.crt"
	certFile        = "./testdata/rsa2048.crt"
	keyFile         = "./testdata/rsa2048.key"
)

func Test_validateX5(t *testing.T) {
	type test struct {
		cf  string
		key interface{}
		err error
	}
	tests := map[string]func() test{
		"fail/certFile-empty-string": func() test {
			return test{
				cf:  "",
				key: nil,
				err: errors.New("certfile cannot be empty"),
			}
		},
		"fail/invalid-cert": func() test {
			return test{
				cf:  invalidCertFile,
				key: nil,
				err: errors.New("error reading certificate chain from file"),
			}
		},
		"fail/bad-key": func() test {
			return test{
				cf:  certFile,
				key: nil,
				err: errors.New("error verifying certificate and key"),
			}
		},
		"fail/cert-not-approved-for-digital-signature": func() test {
			k, err := pemutil.Read(badKeyFile)
			assert.FatalError(t, err)
			return test{
				cf:  badCertFile,
				key: k,
				err: errors.New("certificate/private-key pair used to sign " +
					"token is not approved for digital signature"),
			}
		},
		"ok": func() test {
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			return test{
				cf:  certFile,
				key: k,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if certs, err := validateX5(tc.cf, tc.key); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.NotNil(t, certs)
			}
		})
	}
}

func TestValidateX5T(t *testing.T) {
	type test struct {
		cf  string
		key interface{}
		fp  string
		err error
	}
	tests := map[string]func() test{
		"fail/validateX5-error": func() test {
			return test{
				cf:  "",
				key: nil,
				err: errors.New("ValidateX5T: certfile cannot be empty"),
			}
		},
		"ok": func() test {
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			cert, err := pemutil.ReadCertificate(certFile)
			assert.FatalError(t, err)
			// x5t is the base64 URL encoded SHA1 thumbprint
			// (see https://tools.ietf.org/html/rfc7515#section-4.1.7)
			fp := sha1.Sum(cert.Raw)
			return test{
				cf:  certFile,
				key: k,
				fp:  base64.URLEncoding.EncodeToString(fp[:]),
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if fingerprint, err := ValidateX5T(tc.cf, tc.key); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Equals(t, tc.fp, fingerprint)
			}
		})
	}
}

func TestValidateX5C(t *testing.T) {
	type test struct {
		cf  string
		key interface{}
		err error
	}
	tests := map[string]func() test{
		"fail/validateX5-error": func() test {
			return test{
				cf:  "",
				key: nil,
				err: errors.New("ValidateX5C: certfile cannot be empty"),
			}
		},
		"ok": func() test {
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			return test{
				cf:  certFile,
				key: k,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if certs, err := ValidateX5C(tc.cf, tc.key); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Equals(t, []string{`MIIDCTCCAfGgAwIBAgIQIdY8a5pFZ/FGUowvuGdJvTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTIwMDQyMTA0MDg0MFoXDTIwMDQyMjA0MDg0MFowDzENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0zsTneONS0eNto7LMlD8GtcUYXqILSEWD07v0HgbIguBT+yC8BozpAT3lyB+oBBZkFLzfEHAteULngPwlq0R5hsEZJ6lcL1Z9WXwyLE4nkEndIPMA+zQmHnOzoqgKy7pIqUnFqSGXtGp384fFF3Y0/qjeFciLnmf+Wn0PneaToY1rDj2Eb9sFf5UDiVaSLT1NzpSyXOS5uGbGplPe+WE8uEb3u3Vg2VGbEPau2l5MPYroCwSyxqlpKsmzJ558uvjQ7KpRExSNdb6f0iRfdRMbw3LahrxhbKV1mmM6GD5onmbgBCZpw5htOJj1MzVFZOdnoTHmMl/Y/IUdMjv0jG/UCAwEAAaNhMF8wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUXlQCQL6RymQZnvqY15F/GlE3H4UwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQsFAAOCAQEArVmOL5L+NVsnCcUWfOVXQYg/6P8AGdPJBECk+BE5pbtMg0GuH5Ml/vCTBqD+diWC4O0TZDxPMhXH5Ehl+67hcqeu4riwB2WvvKOlAqHqIuqVDRHtxwknvS1efstBKVdDC6aAfIa5f2dmCSxvd8elpcnufEefLGALTSPxg4uMVvpfWUkkmpmvOUpI3gNrlvP2H4KZk7hKYz+J4x2jv2pdPWUAtt1U4M8oQ4BCPrrHSxznw2Q5mdCMIB64ZeYnZ+rAMQS6WnZy1fTC3d0pCs0UCXH5JefBpha1clqHDUkxHA6/1EYYsSlKGFaPEmfv2uw7MFz0o+yntG34KVdsC8HO3g==`}, certs)
			}
		})
	}
}
