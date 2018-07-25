package x509

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	spem "github.com/smallstep/cli/crypto/pem"
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
			err:     errors.Errorf("error parsing PEM: asn1"),
		},
		"success": {
			crtPath: testCert,
			keyPath: noPasscodeKey,
			pass:    "",
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		var (
			err error
			i   *Identity
		)
		if test.pass == "" {
			i, err = LoadIdentityFromDisk(test.crtPath, test.keyPath)
		} else {
			i, err = LoadIdentityFromDisk(test.crtPath, test.keyPath,
				spem.WithPassword([]byte(test.pass)))
		}
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			assert.FatalError(t, err)
			assert.NotNil(t, i.Crt)
			assert.NotNil(t, i.CrtPem)
			assert.NotNil(t, i.Key)
		}
	}
}
