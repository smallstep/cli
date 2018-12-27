package pemutil

import (
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/smallstep/assert"
)

func TestEncryptDecryptPKCS8(t *testing.T) {
	password := []byte("mypassword")
	for fn, td := range files {
		// skip encrypted and public keys
		if td.encrypted || td.typ == rsaPublicKey || td.typ == ecdsaPublicKey || td.typ == ed25519PublicKey {
			continue
		}

		data, err := ioutil.ReadFile(fn)
		assert.FatalError(t, err)

		key1, err := Parse(data)
		if err != nil {
			t.Errorf("failed to parse %s: %v", fn, err)
			continue
		}

		data, err = MarshalPKCS8PrivateKey(key1)
		if err != nil {
			t.Errorf("failed to marshal private key for %s: %v", fn, err)
			continue
		}

		for _, alg := range rfc1423Algos {
			encBlock, err := EncryptPKCS8PrivateKey(rand.Reader, data, password, alg.cipher)
			if err != nil {
				t.Errorf("failed to decrypt %s with %s: %v", fn, alg.name, err)
				continue
			}
			assert.Equals(t, "ENCRYPTED PRIVATE KEY", encBlock.Type)
			assert.NotNil(t, encBlock.Bytes)
			assert.Nil(t, encBlock.Headers)

			data, err = DecryptPKCS8PrivateKey(encBlock.Bytes, password)
			if err != nil {
				t.Errorf("failed to decrypt %s with %s: %v", fn, alg.name, err)
				continue
			}

			key2, err := ParsePKCS8PrivateKey(data)
			if err != nil {
				t.Errorf("failed to parse PKCS#8 key %s: %v", fn, err)
				continue
			}

			assert.Equals(t, key1, key2)
		}
	}
}
