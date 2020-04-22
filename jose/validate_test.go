package jose

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/smallstep/assert"
)

var (
	badCertFile = "./testdata/bad-rsa.crt"
	badKeyFile  = "./testdata/bad-rsa.key"
	invalidCert = "./testdata/invalid.crt"
	certfile    = "./testdata/rsa2048.crt"
	keyfile     = "./testdata/rsa2048.key"
)

func TestValidateX5T(t *testing.T) {
	var err error

	// test empty file
	_, err = ValidateX5T("", nil)
	assert.Error(t, err, "expected error for empty certfile")

	// test invalid cert
	_, err = ValidateX5T(invalidCert, nil)
	assert.Error(t, err, "expected error for invalid cert")

	// test invalid key
	_, err = ValidateX5T(certfile, nil)
	assert.Error(t, err, "expected error for invalid key")

	// test cert not approved for DigitalSignature
	{
		keyBytes, err := ioutil.ReadFile(badKeyFile)
		if err != nil {
			t.Errorf("unable to read badKeyFile=%q: %s", badKeyFile, err)
			return
		}
		keyBlock, _ := pem.Decode(keyBytes)
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Errorf("unable to parse badKeyFile=%q: %s", badKeyFile, err)
			return
		}
		_, err = ValidateX5T(badCertFile, key)
		assert.Error(t, err, "expected error for cert without digital signature")
	}

	certBytes, err := ioutil.ReadFile(certfile)
	if err != nil {
		t.Errorf("unable to read certfile=%q: %s", certfile, err)
		return
	}
	certBlock, _ := pem.Decode(certBytes)
	digest := sha1.Sum(certBlock.Bytes)
	want := base64.URLEncoding.EncodeToString(digest[:])

	keyBytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		t.Errorf("unable to read keyfile=%q: %s", keyfile, err)
		return
	}

	keyBlock, _ := pem.Decode(keyBytes)
	key, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	got, err := ValidateX5T(certfile, key)
	if err != nil {
		t.Errorf("ValidateX5T(%q, %q) error: %s", certfile, keyfile, err)
	}

	assert.Equals(t, want, got, fmt.Sprintf("ValidateX5T(%s, %s)", certfile, keyfile))
}
