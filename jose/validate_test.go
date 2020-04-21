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
	certfile = "./testdata/rsa2048.crt"
	keyfile  = "./testdata/rsa2048.key"
)

func TestValidateX5T(t *testing.T) {
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
