package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func Test_GenerateKey_unrecognizedkt(t *testing.T) {
	var failTests = []struct {
		kt       string
		crv      string
		bits     int
		expected string
	}{
		{"shake and bake", "", 2048, "unrecognized key type: shake and bake"},
		{"EC", "P-12", 0, "invalid value for argument crv (crv: 'P-12')"},
	}

	for i, tc := range failTests {
		k, err := GenerateKey(tc.kt, tc.crv, tc.bits)
		if assert.Error(t, err, i) {
			assert.HasPrefix(t, err.Error(), tc.expected)
			assert.Nil(t, k)
		}
	}

	var ecdsaTests = []struct {
		kt  string
		crv string
	}{
		{"EC", "P-256"},
		{"EC", "P-384"},
		{"EC", "P-521"},
	}

	for i, tc := range ecdsaTests {
		k, err := GenerateKey(tc.kt, tc.crv, 0)
		if assert.NoError(t, err, i) {
			_, ok := k.(*ecdsa.PrivateKey)
			assert.True(t, ok, i)
		}
	}

	k, err := GenerateKey("RSA", "", 2048)
	if assert.NoError(t, err) {
		_, ok := k.(*rsa.PrivateKey)
		assert.True(t, ok)
	}
}

func Test_PrivatePEM(t *testing.T) {
	oldX509EncryptPEMBlock := x509EncryptPEMBlock
	oldX509MarshalECPrivateKey := x509MarshalECPrivateKey

	var clean = func() {
		x509EncryptPEMBlock = oldX509EncryptPEMBlock
		x509MarshalECPrivateKey = oldX509MarshalECPrivateKey
	}
	defer clean()

	tests := map[string]struct {
		key    func() (interface{}, error)
		pass   string
		cipher x509.PEMCipher
		setup  func()
		clean  func()
		err    error
	}{
		"unrecognized key type": {
			key: func() (interface{}, error) {
				return "shake and bake", nil
			},
			pass:   "pass",
			cipher: x509.PEMCipherAES256,
			err:    errors.New("Unrecognized key - type: string, value: shake and bake"),
		},
		"RSA: encrypt PEM block error": {
			key: func() (interface{}, error) {
				return GenerateKey("RSA", "", 1024)
			},
			pass:   "pass",
			cipher: x509.PEMCipherAES256,
			setup: func() {
				x509EncryptPEMBlock = func(r io.Reader, s string, d, p []byte, alg x509.PEMCipher) (*pem.Block, error) {
					return nil, errors.Errorf("force EncryptPEMBlock error")
				}
			},
			clean: clean,
			err:   errors.New("force EncryptPEMBlock error"),
		},
		"EC: marshal key error": {
			key: func() (interface{}, error) {
				return GenerateKey("EC", "P-256", 0)
			},
			pass:   "pass",
			cipher: x509.PEMCipherAES256,
			setup: func() {
				x509MarshalECPrivateKey = func(k *ecdsa.PrivateKey) ([]byte, error) {
					return nil, errors.Errorf("force MarshalECPrivateKey error")
				}
			},
			clean: clean,
			err:   errors.New("Unable to marshal EC private key: force MarshalECPrivateKey error"),
		},
		"EC: encrypt PEM block error": {
			key: func() (interface{}, error) {
				return GenerateKey("EC", "P-256", 0)
			},
			pass:   "pass",
			cipher: x509.PEMCipherAES256,
			setup: func() {
				x509EncryptPEMBlock = func(r io.Reader, s string, d, p []byte, alg x509.PEMCipher) (*pem.Block, error) {
					return nil, errors.Errorf("force EncryptPEMBlock error")
				}
			},
			clean: clean,
			err:   errors.New("force EncryptPEMBlock error"),
		},
		"RSA: empty password generates unencrypted PEM block - success": {
			key: func() (interface{}, error) {
				return GenerateKey("RSA", "", 1024)
			},
		},
		"EC: empty password generates unencrypted PEM block - success": {
			key: func() (interface{}, error) {
				return GenerateKey("EC", "P-256", 0)
			},
		},
		"EC: encrypt - success": {
			key: func() (interface{}, error) {
				return GenerateKey("EC", "P-256", 0)
			},
			pass:   "pass",
			cipher: x509.PEMCipherAES256,
		},
		"RSA: encrypt - success": {
			key: func() (interface{}, error) {
				return GenerateKey("RSA", "", 256)
			},
			pass:   "pass",
			cipher: x509.PEMCipherAES256,
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		priv, err := test.key()
		assert.FatalError(t, err)

		if test.setup != nil {
			test.setup()
		}
		p, err := PrivatePEM(priv, &EncOpts{test.pass, test.cipher})
		if test.clean != nil {
			test.clean()
		}
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			if assert.Nil(t, test.err) {
				switch k := priv.(type) {
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
				case *ecdsa.PrivateKey:
					if test.pass == "" {
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						assert.Equals(t, p.Type, "EC PRIVATE KEY")

						b, err := x509MarshalECPrivateKey(k)
						assert.FatalError(t, err)
						assert.Equals(t, p.Bytes, b)
					} else {
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equals(t, p.Type, "EC PRIVATE KEY")
						assert.Equals(t, p.Headers["Proc-Type"], "4,ENCRYPTED")

						der, err := x509.DecryptPEMBlock(p, []byte(test.pass))
						assert.FatalError(t, err)
						plain, err := x509.MarshalECPrivateKey(k)
						assert.FatalError(t, err)
						assert.Equals(t, der, plain)
					}
				default:
					t.Errorf("Unrecognized key - type: %T, value: %v", k, k)
				}
			}
		}
	}
}

// empty private key path throws error
func Test_LoadPrivateKey(t *testing.T) {
	tests := map[string]struct {
		bytes       []byte
		getPass     func() (string, error)
		err         error
		resultBytes []byte
	}{
		"input bytes are not PEM formatted": {
			bytes: nil,
			err:   errors.New("invalid key - key is not PEM formatted"),
		},
		"getPass is nil": {
			bytes: []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,544d87909c73e30d2f43fe21b6bc6caf

uir6r8TrhNuXTs6ZF2avaqaLX5cpuh+oTyoS+5Wk0Cbr3NQuAg1l/ZuRI8NWKBt2
nnAXpKSOVnfut9i95ifaOf38mzdDKf8r8vAAVlT9nduzizTcc25Bst2ljSuSuOMP
eCye1+g47hWU2hbxKF1NH9LfJsS7W90LKEuSCKZljz0=
-----END EC PRIVATE KEY-----`),
			getPass: nil,
			err:     errors.New("private key needs a decryption passphrase"),
		},
		"propagate getPass error": {
			bytes: []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,544d87909c73e30d2f43fe21b6bc6caf

uir6r8TrhNuXTs6ZF2avaqaLX5cpuh+oTyoS+5Wk0Cbr3NQuAg1l/ZuRI8NWKBt2
nnAXpKSOVnfut9i95ifaOf38mzdDKf8r8vAAVlT9nduzizTcc25Bst2ljSuSuOMP
eCye1+g47hWU2hbxKF1NH9LfJsS7W90LKEuSCKZljz0=
-----END EC PRIVATE KEY-----`),
			getPass: func() (string, error) {
				return "", errors.Errorf("force getPass error")
			},
			err: errors.New("force getPass error"),
		},
		"propagate decryptPEMBlock error": {
			bytes: []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,544d87909c73e30d2f43fe21b6bc6caf

uir6r8TrhNuXTs6ZF2avaqaLX5cpuh+oTyoS+5Wk0Cbr3NQuAg1l/ZuRI8NWKBt2
nnAXpKSOVnfut9i95ifaOf38mzdDKf8r8vAAVlT9nduzizTcc25Bst2ljSuSuOMP
eCye1+g47hWU2hbxKF1NH9LfJsS7W90LKEuSCKZljz0=
-----END EC PRIVATE KEY-----`),
			getPass: func() (string, error) {
				return "ricky-bobby", nil
			},
			err: errors.New("x509: decryption password incorrect"),
		},
		"EC: encrypted success": {
			bytes: []byte(`-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,544d87909c73e30d2f43fe21b6bc6caf

uir6r8TrhNuXTs6ZF2avaqaLX5cpuh+oTyoS+5Wk0Cbr3NQuAg1l/ZuRI8NWKBt2
nnAXpKSOVnfut9i95ifaOf38mzdDKf8r8vAAVlT9nduzizTcc25Bst2ljSuSuOMP
eCye1+g47hWU2hbxKF1NH9LfJsS7W90LKEuSCKZljz0=
-----END EC PRIVATE KEY-----`),
			resultBytes: []byte{48, 119, 2, 1, 1, 4, 32, 143, 215, 97, 167, 20, 68, 24, 34, 8, 221, 52, 8, 69, 10, 212, 144, 108, 53, 76, 164, 150, 247, 133, 247, 71, 39, 38, 148, 250, 36, 124, 179, 160, 10, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 161, 68, 3, 66, 0, 4, 181, 104, 199, 201, 196, 120, 38, 193, 82, 208, 46, 198, 19, 153, 195, 113, 207, 143, 99, 212, 191, 242, 188, 32, 78, 244, 154, 187, 49, 128, 223, 46, 11, 21, 137, 216, 237, 138, 98, 170, 118, 224, 239, 136, 220, 61, 82, 84, 223, 146, 99, 150, 190, 165, 18, 63, 69, 21, 10, 52, 48, 16, 128, 173},
			getPass: func() (string, error) {
				return "pass", nil
			},
		},
		"EC: un-encrypted success": {
			bytes: []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJhTbozTaR/CoOj7yZIhyteXaYXxW/4RF6D/pMA2y4XeoAoGCCqGSM49
AwEHoUQDQgAERpymPrkl64FD4vPlljJaoc5rMhTdWZsk/G1H/X7mDtlDhoHmrRp5
aJ6EbWtKrZ0+Eb82rZW207IzoTJFnpFPdA==
-----END EC PRIVATE KEY-----`),
			resultBytes: []byte{48, 119, 2, 1, 1, 4, 32, 152, 83, 110, 140, 211, 105, 31, 194, 160, 232, 251, 201, 146, 33, 202, 215, 151, 105, 133, 241, 91, 254, 17, 23, 160, 255, 164, 192, 54, 203, 133, 222, 160, 10, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 161, 68, 3, 66, 0, 4, 70, 156, 166, 62, 185, 37, 235, 129, 67, 226, 243, 229, 150, 50, 90, 161, 206, 107, 50, 20, 221, 89, 155, 36, 252, 109, 71, 253, 126, 230, 14, 217, 67, 134, 129, 230, 173, 26, 121, 104, 158, 132, 109, 107, 74, 173, 157, 62, 17, 191, 54, 173, 149, 182, 211, 178, 51, 161, 50, 69, 158, 145, 79, 116},
		},
		"RSA: encrypted success": {
			bytes: []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,dfc9d24f6f09f401a4bf297098e414ed

4z6W9hmXmJNj1gNhpzwZy2GWWmzFUrzRmUHZmpJkpW1zObaDWyhlC0dhoexPUHyM
elVwEtIfk4hHW/KUHru5yx83ce8Y29I/FTvYlLjK4R/fF4hskrWyNKOy4WRFeSFy
+h8SqjM+KnTpRrhpZarGaGc32RCSCE1OK0KtFVKXNYYyTQLuD2sEPCR0hj9SkgAq
KsYKSvCl9KJR27iilvhXQ7UvuE32OReth6uJfcyF4uY=
-----END RSA PRIVATE KEY-----`),
			resultBytes: []byte{48, 129, 170, 2, 1, 0, 2, 33, 0, 182, 202, 226, 207, 7, 173, 171, 119, 158, 212, 232, 208, 16, 216, 31, 13, 248, 121, 11, 253, 97, 212, 247, 249, 39, 165, 50, 207, 197, 128, 154, 41, 2, 3, 1, 0, 1, 2, 32, 123, 241, 3, 106, 231, 68, 237, 175, 181, 69, 157, 250, 126, 129, 92, 68, 1, 100, 255, 251, 15, 212, 34, 174, 1, 128, 65, 119, 19, 78, 225, 1, 2, 17, 0, 198, 241, 220, 208, 114, 45, 98, 128, 135, 231, 202, 212, 92, 40, 29, 161, 2, 17, 0, 235, 55, 40, 19, 226, 0, 0, 15, 75, 147, 144, 130, 48, 202, 95, 137, 2, 17, 0, 153, 133, 24, 157, 238, 13, 225, 190, 71, 161, 242, 30, 47, 195, 113, 33, 2, 16, 41, 254, 214, 11, 254, 188, 203, 69, 239, 211, 111, 232, 158, 183, 115, 41, 2, 16, 102, 42, 237, 52, 125, 228, 216, 129, 192, 79, 251, 183, 46, 44, 230, 140},
			getPass: func() (string, error) {
				return "pass", nil
			},
		},
		"RSA: un-encrypted success": {
			bytes: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEA1Yz+DRsCJlrxp+Rka52JIPkaCCIbyj4+EUHao/dyGvMCAwEAAQIg
BUxcOUMESKNU/49hFnJwJn+tfLwOQzu7ozdGe8aclVECEQDq33SrABt4+DOGPTJS
1Cx9AhEA6MKKZ9Y0mLy+Gc/5gAiwLwIRAJTGcNd0nPJWfgS1NPBEl90CEQC3Sjrj
efMBM+AfQ38eK7lRAhEA32j/3N2dXwOlytURq2yl+Q==
-----END RSA PRIVATE KEY-----`),
			resultBytes: []byte{48, 129, 172, 2, 1, 0, 2, 33, 0, 213, 140, 254, 13, 27, 2, 38, 90, 241, 167, 228, 100, 107, 157, 137, 32, 249, 26, 8, 34, 27, 202, 62, 62, 17, 65, 218, 163, 247, 114, 26, 243, 2, 3, 1, 0, 1, 2, 32, 5, 76, 92, 57, 67, 4, 72, 163, 84, 255, 143, 97, 22, 114, 112, 38, 127, 173, 124, 188, 14, 67, 59, 187, 163, 55, 70, 123, 198, 156, 149, 81, 2, 17, 0, 234, 223, 116, 171, 0, 27, 120, 248, 51, 134, 61, 50, 82, 212, 44, 125, 2, 17, 0, 232, 194, 138, 103, 214, 52, 152, 188, 190, 25, 207, 249, 128, 8, 176, 47, 2, 17, 0, 148, 198, 112, 215, 116, 156, 242, 86, 126, 4, 181, 52, 240, 68, 151, 221, 2, 17, 0, 183, 74, 58, 227, 121, 243, 1, 51, 224, 31, 67, 127, 30, 43, 185, 81, 2, 17, 0, 223, 104, 255, 220, 221, 157, 95, 3, 165, 202, 213, 17, 171, 108, 165, 249},
		},
	}
	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		key, err := LoadPrivateKey(test.bytes, test.getPass)
		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.HasPrefix(t, err.Error(), test.err.Error())
			}
		} else {
			if assert.Nil(t, test.err) {
				switch k := key.(type) {
				case *ecdsa.PrivateKey:
					b, err := x509.MarshalECPrivateKey(k)
					assert.FatalError(t, err)
					assert.Equals(t, b, test.resultBytes)
				case *rsa.PrivateKey:
					assert.Equals(t, x509.MarshalPKCS1PrivateKey(k), test.resultBytes)
				default:
					t.Errorf("unrecognized key type %T", k)
				}
			}
		}
	}
}

func Test_WriteKey(t *testing.T) {
	keyOut := "./test.key"
	pass := "pass"

	tests := map[string]struct {
		key    func() (interface{}, error)
		keyOut string
		pass   string
		err    error
	}{
		"propagate open key out file error": {
			key: func() (interface{}, error) {
				return GenerateKey(DefaultKeyType, DefaultKeyCurve, 0)
			},
			keyOut: "./fakeDir/test.key",
			err:    errors.New("failed to open './fakeDir/test.key' for writing: open ./fakeDir/test.key: no such file or directory"),
		},
		"propagate encrypt key error": {
			key: func() (interface{}, error) {
				return GenerateKey(DefaultKeyType, DefaultKeyCurve, 0)
			},
			pass:   pass,
			keyOut: keyOut,
			err:    errors.New("failed to convert private key to PEM block: encryption passphrase cannot be empty"),
		},
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
