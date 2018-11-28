package pemutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	realx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/pkg/x509"
	"golang.org/x/crypto/ed25519"
)

type keyType int

const (
	ecdsaPublicKey keyType = iota
	ecdsaPrivateKey
	ed25519PublicKey
	ed25519PrivateKey
	rsaPublicKey
	rsaPrivateKey
)

type testdata struct {
	typ       keyType
	encrypted bool
}

var files = map[string]testdata{
	"testdata/openssl.p256.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p256.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p256.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.p384.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p384.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p384.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.p521.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p521.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p521.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.rsa1024.pem":           {rsaPrivateKey, false},
	"testdata/openssl.rsa1024.pub.pem":       {rsaPublicKey, false},
	"testdata/openssl.rsa1024.enc.pem":       {rsaPrivateKey, true},
	"testdata/openssl.rsa2048.pem":           {rsaPrivateKey, false},
	"testdata/openssl.rsa2048.pub.pem":       {rsaPublicKey, false},
	"testdata/openssl.rsa2048.enc.pem":       {rsaPrivateKey, true},
	"testdata/pkcs8/openssl.ed25519.pem":     {ed25519PrivateKey, false},
	"testdata/pkcs8/openssl.ed25519.pub.pem": {ed25519PublicKey, false},
	"testdata/pkcs8/openssl.ed25519.enc.pem": {ed25519PrivateKey, true},
	"testdata/pkcs8/openssl.p256.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p256.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p256.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.p384.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p384.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p384.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.p521.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p521.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p521.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.rsa2048.pem":     {rsaPrivateKey, false},
	"testdata/pkcs8/openssl.rsa2048.pub.pem": {rsaPublicKey, false},
	"testdata/pkcs8/openssl.rsa2048.enc.pem": {rsaPrivateKey, true},
	"testdata/pkcs8/openssl.rsa4096.pem":     {rsaPrivateKey, false},
	"testdata/pkcs8/openssl.rsa4096.pub.pem": {rsaPublicKey, false},
}

func TestRead(t *testing.T) {
	var err error
	var key interface{}

	for fn, td := range files {
		if td.encrypted {
			key, err = Read(fn, WithPassword([]byte("mypassword")))
		} else {
			key, err = Read(fn)
		}

		assert.NotNil(t, key)
		assert.NoError(t, err)

		switch td.typ {
		case ecdsaPublicKey:
			assert.Type(t, &ecdsa.PublicKey{}, key)
		case ecdsaPrivateKey:
			assert.Type(t, &ecdsa.PrivateKey{}, key)
		case ed25519PublicKey:
			assert.Type(t, ed25519.PublicKey{}, key)
		case ed25519PrivateKey:
			assert.Type(t, ed25519.PrivateKey{}, key)
		case rsaPublicKey:
			assert.Type(t, &rsa.PublicKey{}, key)
		case rsaPrivateKey:
			assert.Type(t, &rsa.PrivateKey{}, key)
		default:
			t.Errorf("type %T not supported", key)
		}

		// Check encrypted against non-encrypted
		if td.encrypted {
			k, err := Read(strings.Replace(fn, ".enc", "", 1))
			assert.NoError(t, err)
			assert.Equals(t, k, key)
		}

		// Check against public
		switch td.typ {
		case ecdsaPrivateKey, ed25519PrivateKey, rsaPrivateKey:
			pub := strings.Replace(fn, ".enc", "", 1)
			pub = strings.Replace(pub, "pem", "pub.pem", 1)

			k, err := Read(pub)
			assert.NoError(t, err)

			if pk, ok := key.(crypto.Signer); ok {
				assert.Equals(t, k, pk.Public())
			} else {
				t.Errorf("key for %s does not satisfies the crypto.Signer interface", fn)
			}
		}
	}
}

func TestReadCertificate(t *testing.T) {
	tests := []struct {
		fn  string
		err error
	}{
		{"testdata/ca.crt", nil},
		{"testdata/ca.der", nil},
		{"testdata/notexists.crt", errors.New("open testdata/notexists.crt failed: no such file or directory")},
		{"testdata/badca.crt", errors.New("error parsing testdata/badca.crt")},
		{"testdata/badpem.crt", errors.New("error decoding testdata/badpem.crt: is not a valid PEM encoded key")},
		{"testdata/openssl.p256.pem", errors.New("error decoding PEM: file 'testdata/openssl.p256.pem' does not contain a certificate")},
	}

	for _, tc := range tests {
		crt, err := ReadCertificate(tc.fn)
		if tc.err != nil {
			if assert.Error(t, err) {
				assert.HasPrefix(t, err.Error(), tc.err.Error())
			}
		} else {
			assert.NoError(t, err)
			assert.Type(t, &realx509.Certificate{}, crt)
		}
	}
}

func TestReadStepCertificate(t *testing.T) {
	tests := []struct {
		fn  string
		err error
	}{
		{"testdata/ca.crt", nil},
		{"testdata/ca.der", nil},
		{"testdata/notexists.crt", errors.New("open testdata/notexists.crt failed: no such file or directory")},
		{"testdata/badca.crt", errors.New("error parsing testdata/badca.crt")},
		{"testdata/badpem.crt", errors.New("error decoding testdata/badpem.crt: is not a valid PEM encoded key")},
		{"testdata/openssl.p256.pem", errors.New("error decoding PEM: file 'testdata/openssl.p256.pem' does not contain a certificate")},
	}

	for _, tc := range tests {
		crt, err := ReadStepCertificate(tc.fn)
		if tc.err != nil {
			if assert.Error(t, err) {
				assert.HasPrefix(t, err.Error(), tc.err.Error())
			}
		} else {
			assert.NoError(t, err)
			assert.Type(t, &x509.Certificate{}, crt)
		}
	}
}

func TestParsePEM(t *testing.T) {
	type ParseTest struct {
		in      []byte
		opts    []Options
		cmpType interface{}
		err     error
	}
	tests := map[string]func(t *testing.T) *ParseTest{
		"success-ecdsa-public-key": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/openssl.p256.pub.pem")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &ecdsa.PublicKey{},
			}
		},
		"success-rsa-public-key": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/openssl.rsa1024.pub.pem")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &rsa.PublicKey{},
			}
		},
		"success-rsa-private-key": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/openssl.rsa1024.pem")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &rsa.PrivateKey{},
			}
		},
		"success-ecdsa-private-key": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/openssl.p256.pem")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &ecdsa.PrivateKey{},
			}
		},
		"success-ed25519-private-key": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/pkcs8/openssl.ed25519.pem")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: ed25519.PrivateKey{},
			}
		},
		"success-ed25519-enc-private-key": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/pkcs8/openssl.ed25519.enc.pem")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{WithPassword([]byte("mypassword"))},
				cmpType: ed25519.PrivateKey{},
			}
		},
		"success-x509-crt": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/ca.crt")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &realx509.Certificate{},
			}
		},
		"success-stepx509-crt": func(t *testing.T) *ParseTest {
			b, err := ioutil.ReadFile("testdata/ca.crt")
			assert.FatalError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{WithStepCrypto()},
				cmpType: &x509.Certificate{},
			}
		},
	}
	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			i, err := Parse(tc.in, tc.opts...)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Type(t, i, tc.cmpType)
				}
			}
		})
	}

}

func TestSerialize(t *testing.T) {
	tests := map[string]struct {
		in   func() (interface{}, error)
		pass string
		file string
		err  error
	}{
		"unrecognized key type": {
			in: func() (interface{}, error) {
				return "shake and bake", nil
			},
			err: errors.New("cannot serialize type 'string', value 'shake and bake'"),
		},
		"RSA Private Key success": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("RSA", "", 1024)
			},
		},
		"RSA Public Key success": {
			in: func() (interface{}, error) {
				pub, _, err := keys.GenerateKeyPair("RSA", "", 1024)
				return pub, err
			},
		},
		"EC Private Key success": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("EC", "P-256", 0)
			},
		},
		"EC Private Key success - encrypt input data": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("EC", "P-256", 0)
			},
			pass: "pass",
		},
		"EC Public Key success": {
			in: func() (interface{}, error) {
				pub, _, err := keys.GenerateKeyPair("EC", "P-256", 0)
				return pub, err
			},
		},
		"OKP Private Key success": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("OKP", "Ed25519", 0)
			},
		},
		"OKP Public Key success": {
			in: func() (interface{}, error) {
				pub, _, err := keys.GenerateKeyPair("OKP", "Ed25519", 0)
				return pub, err
			},
		},
		"propagate open key out file error": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("EC", "P-256", 0)
			},
			file: "./fakeDir/test.key",
			err:  errors.New("open ./fakeDir/test.key failed: no such file or directory"),
		},
		"ToFile Success (EC Private Key unencrypted)": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("EC", "P-256", 0)
			},
			file: "./test.key",
		},
		"ToFile Success (EC Private Key encrypted)": {
			in: func() (interface{}, error) {
				return keys.GenerateKey("EC", "P-256", 0)
			},
			pass: "pass",
			file: "./test.key",
		},
	}

	for name, test := range tests {
		if _, err := os.Stat("./test.key"); err == nil {
			assert.FatalError(t, os.Remove("./test.key"))
		}
		t.Logf("Running test case: %s", name)

		in, err := test.in()
		assert.FatalError(t, err)

		var p *pem.Block
		if test.pass == "" && test.file == "" {
			p, err = Serialize(in)
		} else if test.pass != "" && test.file != "" {
			p, err = Serialize(in, WithEncryption([]byte(test.pass)), ToFile(test.file, 0600))
		} else if test.pass != "" {
			p, err = Serialize(in, WithEncryption([]byte(test.pass)))
		} else {
			p, err = Serialize(in, ToFile(test.file, 0600))
		}

		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			if assert.Nil(t, test.err) {
				switch k := in.(type) {
				case *rsa.PrivateKey:
					if test.pass == "" {
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						assert.Equals(t, p.Type, "RSA PRIVATE KEY")
						assert.Equals(t, p.Bytes, x509.MarshalPKCS1PrivateKey(k))
					} else {
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equals(t, p.Type, "RSA PRIVATE KEY")
						assert.Equals(t, p.Headers["Proc-Type"], "4,ENCRYPTED")

						der, err := x509.DecryptPEMBlock(p, []byte(test.pass))
						assert.FatalError(t, err)
						assert.Equals(t, der, x509.MarshalPKCS1PrivateKey(k))
					}
				case *rsa.PublicKey, *ecdsa.PublicKey:
					assert.False(t, x509.IsEncryptedPEMBlock(p))
					assert.Equals(t, p.Type, "PUBLIC KEY")

					b, err := x509.MarshalPKIXPublicKey(k)
					assert.FatalError(t, err)
					assert.Equals(t, p.Bytes, b)
				case *ecdsa.PrivateKey:
					assert.Equals(t, p.Type, "EC PRIVATE KEY")
					var actualBytes []byte
					if test.pass == "" {
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						actualBytes = p.Bytes
					} else {
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equals(t, p.Headers["Proc-Type"], "4,ENCRYPTED")

						actualBytes, err = x509.DecryptPEMBlock(p, []byte(test.pass))
						assert.FatalError(t, err)
					}
					expectedBytes, err := x509.MarshalECPrivateKey(k)
					assert.FatalError(t, err)
					assert.Equals(t, actualBytes, expectedBytes)

					if test.file != "" {
						// Check key permissions
						fileInfo, err := os.Stat(test.file)
						assert.FatalError(t, err)
						assert.Equals(t, fileInfo.Mode(), os.FileMode(0600))
						// Verify that key written to file is correct
						keyFileBytes, err := ioutil.ReadFile(test.file)
						assert.FatalError(t, err)
						pemKey, _ := pem.Decode(keyFileBytes)
						assert.Equals(t, pemKey.Type, "EC PRIVATE KEY")
						if x509.IsEncryptedPEMBlock(pemKey) {
							assert.Equals(t, pemKey.Headers["Proc-Type"], "4,ENCRYPTED")
							actualBytes, err = x509.DecryptPEMBlock(pemKey, []byte(test.pass))
							assert.FatalError(t, err)
						} else {
							actualBytes = pemKey.Bytes
						}
						assert.Equals(t, actualBytes, expectedBytes)
					}
				case ed25519.PrivateKey:
					assert.Equals(t, p.Type, "PRIVATE KEY")
					var actualBytes []byte
					if test.pass == "" {
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						actualBytes = p.Bytes
					} else {
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equals(t, p.Headers["Proc-Type"], "4,ENCRYPTED")

						actualBytes, err = x509.DecryptPEMBlock(p, []byte(test.pass))
						assert.FatalError(t, err)
					}

					var priv pkcs8
					_, err = asn1.Unmarshal(actualBytes, &priv)
					assert.FatalError(t, err)
					assert.Equals(t, priv.Version, 0)
					assert.Equals(t, priv.Algo, pkix.AlgorithmIdentifier{
						Algorithm:  asn1.ObjectIdentifier{1, 3, 101, 112},
						Parameters: asn1.RawValue{},
					})
					assert.Equals(t, priv.PrivateKey[:2], []byte{4, 32})
					assert.Equals(t, priv.PrivateKey[2:ed25519.SeedSize+2], k.Seed())
				case ed25519.PublicKey:
					assert.Equals(t, p.Type, "PUBLIC KEY")
					assert.False(t, x509.IsEncryptedPEMBlock(p))

					var pub publicKeyInfo
					_, err = asn1.Unmarshal(p.Bytes, &pub)
					assert.FatalError(t, err)
					assert.Equals(t, pub.Algo, pkix.AlgorithmIdentifier{
						Algorithm:  asn1.ObjectIdentifier{1, 3, 101, 112},
						Parameters: asn1.RawValue{},
					})
					assert.Equals(t, pub.PublicKey, asn1.BitString{
						Bytes:     k,
						BitLength: ed25519.PublicKeySize * 8,
					})
				default:
					t.Errorf("Unrecognized key - type: %T, value: %v", k, k)
				}
			}
		}
		if _, err := os.Stat("./test.key"); err == nil {
			assert.FatalError(t, os.Remove("./test.key"))
		}
	}
}

/*
func TestWriteKey(t *testing.T) {
	keyOut := "./test.key"
	pass := "pass"

	tests := map[string]struct {
		key    func() (interface{}, error)
		keyOut string
		pass   string
		err    error
	}{
		"success": {
			key: func() (interface{}, error) {
				return GenerateKey(DefaultKeyType, DefaultKeyCurve, 0)
			},
			keyOut: keyOut,
			pass:   pass,
			err:    errors.New("failed to convert private key to PEM block: encryption passphrase cannot be empty"),
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		key, err := test.key()
		assert.FatalError(t, err)

		err = WritePrivateKey(key, test.pass, test.keyOut)
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			// Check key permissions
			fileInfo, err := os.Stat(test.keyOut)
			assert.FatalError(t, err)
			fileMode := fileInfo.Mode()
			if fileMode != 0600 {
				t.Errorf("FileMode mismatch for file %s -- expected: `%d`, but got: `%d`",
					test.keyOut, fileMode, 0600)
			}

			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				// Verify that key written to file is correct
				plain, err := x509.MarshalECPrivateKey(k)
				assert.FatalError(t, err)
				keyFileBytes, err := ioutil.ReadFile(test.keyOut)
				assert.FatalError(t, err)
				pemKey, _ := pem.Decode(keyFileBytes)
				assert.True(t, x509.IsEncryptedPEMBlock(pemKey))
				assert.Equals(t, pemKey.Type, "EC PRIVATE KEY")
				assert.Equals(t, pemKey.Headers["Proc-Type"], "4,ENCRYPTED")
				der, err := x509.DecryptPEMBlock(pemKey, []byte(pass))
				assert.FatalError(t, err)
				assert.Equals(t, der, plain)
			default:
				t.Errorf("unexpected key type %T", k)
			}
		}
	}
}
*/
