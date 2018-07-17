package x509

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func Test_LoadIdentityFromDisk(t *testing.T) {
	var (
		testBadCert          = "./test_files/badca.crt"
		testCert             = "./test_files/ca.crt"
		testNoPasscodeBadKey = "./test_files/noPasscodeBadCa.key"
		noPasscodeKey        = "./test_files/noPasscodeCa.key"
	)

	tests := map[string]struct {
		crtPath string
		keyPath string
		pass    string
		err     error
	}{
		"error parsing x509 certificate": {
			crtPath: testBadCert,
			keyPath: "",
			pass:    "",
			err: errors.Errorf("error parsing x509 certificate file %s",
				testBadCert),
		},
		"error parsing rsa key": {
			crtPath: testCert,
			keyPath: testNoPasscodeBadKey,
			pass:    "",
			err:     errors.Errorf("error parsing RSA key"),
		},
		"success": {
			crtPath: testCert,
			keyPath: noPasscodeKey,
			pass:    "",
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		kp, err := LoadIdentityFromDisk(test.crtPath, test.keyPath, func() (string, error) {
			return test.pass, nil
		})
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			assert.FatalError(t, err)
			assert.NotNil(t, kp.Crt)
			assert.NotNil(t, kp.CrtPem)
			assert.NotNil(t, kp.Key)
		}
	}
}
