package pemutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"reflect"
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

func TestMarshalPKIXPublicKey(t *testing.T) {
	mustPKIX := func(pub interface{}) []byte {
		b, err := x509.MarshalPKIXPublicKey(pub)
		assert.FatalError(t, err)
		return b
	}

	rsaKey, err := Read("testdata/openssl.rsa2048.pub.pem")
	assert.FatalError(t, err)
	ecdsaKey, err := Read("testdata/openssl.p256.pub.pem")
	assert.FatalError(t, err)
	edKey, err := Read("testdata/pkcs8/openssl.ed25519.pem")
	assert.FatalError(t, err)
	edPubDer, err := ioutil.ReadFile("testdata/pkcs8/openssl.ed25519.pub.der")
	assert.FatalError(t, err)

	type args struct {
		pub interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"rsa", args{rsaKey}, mustPKIX(rsaKey), false},
		{"ecdsa", args{ecdsaKey}, mustPKIX(ecdsaKey), false},
		{"ed25519", args{edKey.(ed25519.PrivateKey).Public()}, edPubDer, false},
		{"fail", args{edKey}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalPKIXPublicKey(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalPKIXPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalPKIXPublicKey() = \n got %v, \nwant %v", got, tt.want)
			}
		})
	}
}

func TestMarshalPKCS8PrivateKey(t *testing.T) {
	mustPKCS8 := func(pub interface{}) []byte {
		b, err := x509.MarshalPKCS8PrivateKey(pub)
		assert.FatalError(t, err)
		return b
	}

	rsaKey, err := Read("testdata/openssl.rsa2048.pem")
	assert.FatalError(t, err)
	ecdsaKey, err := Read("testdata/openssl.p256.pem")
	assert.FatalError(t, err)
	edKey, err := Read("testdata/pkcs8/openssl.ed25519.pem")
	assert.FatalError(t, err)
	edPrivDer, err := ioutil.ReadFile("testdata/pkcs8/openssl.ed25519.der")
	assert.FatalError(t, err)

	type args struct {
		key interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"rsa", args{rsaKey}, mustPKCS8(rsaKey), false},
		{"ecdsa", args{ecdsaKey}, mustPKCS8(ecdsaKey), false},
		{"ed25519", args{edKey}, edPrivDer, false},
		{"fail", args{edKey.(ed25519.PrivateKey).Public()}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalPKCS8PrivateKey(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalPKCS8PrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalPKCS8PrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
