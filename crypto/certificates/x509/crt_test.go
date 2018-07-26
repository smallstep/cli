package x509

import (
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/pkg/x509"
)

func Test_WriteCertificate(t *testing.T) {
	certPath := "./test.crt"

	tests := map[string]struct {
		crt    func() ([]byte, error)
		crtOut string
		err    error
	}{
		"crt cannot be nil": {
			crt: func() ([]byte, error) {
				return nil, nil
			},
			err: errors.New("crt cannot be nil"),
		},
		"propagate open crt out file error": {
			crt: func() ([]byte, error) {
				return []byte{}, nil
			},
			crtOut: "./fakeDir/test.crt",
			err:    errors.New("open ./fakeDir/test.crt failed: no such file or directory"),
		},
		"success": {
			crt: func() ([]byte, error) {
				hosts := "google.com,127.0.0.1,facebook.com,1.1.1.1"
				sub := pkix.Name{
					Country:      []string{"usa"},
					Organization: []string{"smallstep"},
					Locality:     []string{"san francisco"},
					CommonName:   "internal.smallstep.com",
				}
				profile, err := NewRootProfile("overwrite", WithSubject(sub),
					WithIssuer(sub), WithHosts(hosts))
				if err != nil {
					return nil, err
				}
				return profile.CreateCertificate()
			},
			crtOut: certPath,
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		crtBytes, err := test.crt()
		assert.FatalError(t, err)

		err = WriteCertificate(crtBytes, test.crtOut)
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			ctv, err := NewCertTemplate()
			assert.FatalError(t, err)
			ctv.Subject.Country = []string{"usa"}
			ctv.Subject.Organization = []string{"smallstep"}
			ctv.Subject.Locality = []string{"san francisco"}
			ctv.Subject.CommonName = "internal.smallstep.com"
			ctv.Issuer.Country = []string{"usa"}
			ctv.Issuer.Organization = []string{"smallstep"}
			ctv.Issuer.Locality = []string{"san francisco"}
			ctv.Issuer.CommonName = "internal.smallstep.com"
			ctv.DNSNames = []string{"google.com", "facebook.com"}
			ctv.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("1.1.1.1")}
			ctv.IsCA = true
			ctv.KeyUsage |= x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign
			ctv.BasicConstraintsValid = true
			ctv.MaxPathLenZero = false
			ctv.MaxPathLen = 1
			ctv.SignatureAlgorithm = x509.ECDSAWithSHA256
			ctv.PublicKeyAlgorithm = x509.ECDSA
			ctv.Version = 3

			crt, err := x509.ParseCertificate(crtBytes)
			assert.FatalError(t, err)
			pubBytes, err := x509.MarshalPKIXPublicKey(crt.PublicKey)
			assert.FatalError(t, err)
			_hash := sha1.Sum(pubBytes)
			hash := _hash[:]
			ctv.SubjectKeyId = hash[:] // takes slice over the whole array

			// Verify that cert written to file is correct
			certFileBytes, err := ioutil.ReadFile(certPath)
			assert.FatalError(t, err)
			pemCert, _ := pem.Decode(certFileBytes)
			fileCert, err := x509.ParseCertificate(pemCert.Bytes)
			assert.FatalError(t, err)

			// Check `NotBefore` and `NotAfter`.
			now := time.Now().UTC()
			assert.True(t, fileCert.NotBefore.Before(now))
			assert.True(t, fileCert.NotBefore.After(now.Add(-time.Minute)))
			expiry := now.Add(time.Hour * 24 * 365 * 10)
			assert.True(t, fileCert.NotAfter.Before(expiry))
			assert.True(t, fileCert.NotAfter.After(expiry.Add(-time.Minute)))
			// Now we set these to correct values since we've already checked them.
			ctv.NotBefore = fileCert.NotBefore
			ctv.NotAfter = fileCert.NotAfter

			assert.NoError(t, ctv.Compare(CertTemplate(*fileCert)))
		}
	}
}

func Test_LoadCertificate(t *testing.T) {
	var (
		testBadCert    = "./test_files/badca.crt"
		testBadPEMCert = "./test_files/badpem.crt"
		testCert       = "./test_files/ca.crt"
	)

	tests := map[string]struct {
		crtPath string
		err     error
	}{
		"certificate file does not exist": {
			crtPath: "<path>",
			err:     errors.New("open <path> failed: no such file or directory"),
		},
		"certificate poorly formatted - PEM decode failure": {
			crtPath: testBadPEMCert,
			err:     errors.New("error decoding certificate file"),
		},
		"certificate parse failure": {
			crtPath: testBadCert,
			err:     errors.New("error parsing x509 certificate file"),
		},
		"success": {
			crtPath: testCert,
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		crt, block, err := LoadCertificate(test.crtPath)
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			assert.Equals(t, crt.Subject.CommonName, "internal.smallstep.com")
			assert.NotNil(t, block)
		}
	}
}
