//go:build integration
// +build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/randutil"
	jose "gopkg.in/square/go-jose.v2"
)

func AssertFileExists(t *testing.T, path string, a ...interface{}) bool {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			assert.FatalError(t, err, fmt.Sprintf("unable to find file %q", path), a)
		}
		assert.FatalError(t, err, fmt.Sprintf("error when running os.Lstat(%q): %s", path, err), a)
	}
	assert.Fatal(t, !info.IsDir(), fmt.Sprintf("%q is a directory", path), a)
	assert.Equals(t, int(info.Mode()), 0600)
	return true
}

type JWKTest struct {
	name    string
	pubfile string
	prvfile string
	command CLICommand
}

func NewJWKTest(name string) JWKTest {
	pubfile := fmt.Sprintf("%s/%s-pub.json", TempDirectory, name)
	prvfile := fmt.Sprintf("%s/%s-prv.json", TempDirectory, name)
	cmd := NewCLICommand().setCommand("step crypto jwk create").setArguments(fmt.Sprintf("%s %s", pubfile, prvfile))
	return JWKTest{name, pubfile, prvfile, cmd}
}

func (j JWKTest) setFlag(flag, value string) JWKTest {
	return JWKTest{j.name, j.pubfile, j.prvfile, j.command.setFlag(flag, value)}
}

func (j JWKTest) cmd() string {
	return j.command.cmd()
}

func (j JWKTest) run() (CLIOutput, error) {
	return j.command.run()
}

func (j JWKTest) test(t *testing.T, msg ...interface{}) (CLIOutput, string) {
	var out CLIOutput
	var pass string

	t.Run(j.name, func(t *testing.T) {
		// fmt.Printf("Running command: %s\n", j.cmd())
		e, err := j.command.spawn()
		assert.FatalError(t, err)
		if _, ok := j.command.flags["no-password"]; !ok {
			pass, err = randutil.ASCII(16)
			assert.FatalError(t, err)
			e.ExpectTimeout("Please enter the password to encrypt the private JWK: ", DefaultTimeout)
			e.SendLine(pass)
			e.Interact()
		} else {
			e.Wait()
		}

		AssertFileExists(t, j.pubfile, fmt.Sprintf("step crypto jwk create should create public JWK at %s", j.pubfile))
		AssertFileExists(t, j.prvfile, fmt.Sprintf("step crypto jwk create should create private JWK at %s", j.prvfile))
		j.checkPublic(t)
		j.checkPrivate(t, pass)
	})
	return out, pass
}

func (j JWKTest) readJson(t *testing.T, name string) map[string]interface{} {
	dat, err := os.ReadFile(name)
	assert.FatalError(t, err)
	m := make(map[string]interface{})
	assert.FatalError(t, json.Unmarshal(dat, &m))
	return m
}

func (j JWKTest) public(t *testing.T) map[string]interface{} {
	return j.readJson(t, j.pubfile)
}

func (j JWKTest) private(t *testing.T) map[string]interface{} {
	return j.readJson(t, j.prvfile)
}

func (j JWKTest) kty() string {
	// Default "kty" is EC
	kty := "EC"
	if v, ok := j.command.flags["kty"]; ok {
		kty = v
	} else if v, ok = j.command.flags["type"]; ok {
		kty = v
	}
	return kty
}

/*
func (j JWKTest) crv() string {
	if v, ok := j.command.flags["crv"]; ok {
		return v, true
	} else if v, ok = j.command.flags["curve"]; ok {
		return v, true
	}
	return "", false
}
*/

func (j JWKTest) checkPubPriv(t *testing.T, m map[string]interface{}) {

	checkSize := func(v string, defaultSize int) {
		bytes, err := base64.RawURLEncoding.DecodeString(v)
		assert.FatalError(t, err)
		if v, ok := j.command.flags["size"]; ok {
			size, err := strconv.Atoi(v)
			assert.FatalError(t, err)
			assert.Equals(t, len(bytes)*8, size)
		} else {
			assert.Equals(t, len(bytes)*8, defaultSize)
		}
	}

	checkSizeBytes := func(v string, defaultSize int) {
		bytes, err := base64.RawURLEncoding.DecodeString(v)
		assert.FatalError(t, err)
		if v, ok := j.command.flags["size"]; ok {
			size, err := strconv.Atoi(v)
			assert.FatalError(t, err)
			assert.Equals(t, len(bytes), size)
		} else {
			assert.Equals(t, len(bytes), defaultSize)
		}
	}

	kty := j.kty()
	assert.Equals(t, kty, m["kty"])

	if v, ok := j.command.flags["use"]; ok {
		assert.Equals(t, v, m["use"])
	} else {
		// Default "use" is "sig"
		assert.Equals(t, "sig", m["use"])
	}

	if v, ok := j.command.flags["kid"]; ok {
		assert.Equals(t, v, m["kid"])
	} else {
		assert.False(t, "" == m["kid"])
	}

	if kty == "EC" {
		_, ok := m["size"]
		assert.True(t, !ok, "size attribute for EC key")

		if v, ok := j.command.flags["crv"]; ok {
			assert.Equals(t, v, m["crv"])
		} else {
			switch j.command.flags["alg"] {
			case "ES256":
				assert.Equals(t, "P-256", m["crv"])
			case "ES384":
				assert.Equals(t, "P-384", m["crv"])
			case "ES512":
				assert.Equals(t, "P-521", m["crv"])
			default:
				assert.Equals(t, "P-256", m["crv"])
			}
		}

		if v, ok := j.command.flags["alg"]; ok {
			assert.Equals(t, v, m["alg"])
		} else {
			if m["use"] == "enc" {
				assert.Equals(t, "ECDH-ES", m["alg"])
			} else {
				switch m["crv"] {
				case "P-256":
					assert.Equals(t, "ES256", m["alg"])
				case "P-384":
					assert.Equals(t, "ES384", m["alg"])
				case "P-521":
					assert.Equals(t, "ES512", m["alg"])
				}
			}
		}

		// TODO: Check EC parameters and key size
	} else if kty == "OKP" {
		_, ok := m["size"]
		assert.True(t, !ok, "size attribute for OKP key")
		assert.Equals(t, "Ed25519", m["crv"])
		assert.Equals(t, "EdDSA", m["alg"])
		_, ok = m["x"]
		assert.True(t, ok, "JWK with \"kty\" of \"OKP\" should have \"x\" parameter (public key)")
	} else if kty == "RSA" {
		_, ok := m["crv"]
		assert.True(t, !ok, "crv attribute for non-EC key")

		if v, ok := j.command.flags["alg"]; ok {
			assert.Equals(t, v, m["alg"])
		} else {
			// Default "alg" is "RS256" for "RSA" keys
			assert.Equals(t, "RS256", m["alg"])
		}

		n, ok := m["n"]
		assert.True(t, ok, "JWK with \"kty\" of \"RSA\" should have \"n\" parameter (modulus)")
		_, ok = m["e"]
		assert.True(t, ok, "JWK with \"kty\" of \"RSA\" should have \"e\" parameter (exponent)")

		// Check that `n` is the correct size
		checkSize(n.(string), 2048)
	} else if kty == "oct" {
		// Should be no "crv" for non-EC keys
		_, ok := m["crv"]
		assert.True(t, !ok, "crv attribute for non-EC key")

		if v, ok := j.command.flags["alg"]; ok {
			assert.Equals(t, v, m["alg"])
		} else {
			// Default "alg" is "HS256" for "oct" keys
			assert.Equals(t, "HS256", m["alg"])
		}

		k, ok := m["k"]
		assert.True(t, ok, "JWK with \"kty\" of \"oct\" should have \"k\" parameter (key)")

		// Check `k` is correct size
		checkSizeBytes(k.(string), 32)
	} else {
		assert.True(t, false, fmt.Sprintf("invalid key type: %s", kty))
	}
}

func (j JWKTest) checkPublic(t *testing.T) {
	j.checkPubPriv(t, j.public(t))
}

func isJWE(m map[string]interface{}) bool {
	// `ciphertext` which MUST be present in a JWE according to RFC7516
	_, ok := m["ciphertext"]
	return ok
}

func (j JWKTest) decryptJWEPayload(t *testing.T, password string) map[string]interface{} {
	dat, err := os.ReadFile(j.prvfile)
	assert.FatalError(t, err)
	enc, err := jose.ParseEncrypted(string(dat))
	assert.FatalError(t, err)
	dec, err := enc.Decrypt([]byte(password))
	assert.FatalError(t, err)
	m := make(map[string]interface{})
	assert.FatalError(t, json.Unmarshal(dec, &m))
	return m
}

func (j JWKTest) checkPrivate(t *testing.T, password string) {
	m := j.private(t)
	_, nopass := j.command.flags["no-password"]
	if isJWE(m) {
		assert.False(t, nopass, "expected unencrypted JWK with --no-password flag but got JWE")
		hdrb, ok := m["protected"]
		assert.True(t, ok, "missing protected header attribute in JWE")
		hdr, err := base64.RawURLEncoding.DecodeString(hdrb.(string))
		assert.FatalError(t, err)
		// assert.Equals(t, string(hdr), `{"alg":"A128KW","enc":"A128GCM"}`)
		assert.HasPrefix(t, string(hdr), `{"alg":"PBES2-HS256+A128KW","cty":"jwk+json","enc":"A256GCM","p2c":100000,"p2s":"`)
		m = j.decryptJWEPayload(t, password)
	} else {
		assert.True(t, nopass, "JWKs should be encrypted in JWE unless --no-password flag is passed")
	}
	j.checkPubPriv(t, m)
	if j.kty() == "EC" {
		// TODO: Check EC parameters and key size
	} else if j.kty() == "OKP" {
		_, ok := m["d"]
		assert.True(t, ok, "JWK with \"kty\" of \"OKP\" should have \"d\" parameter (private key)")
	} else if j.kty() == "RSA" {
		d, ok := m["d"]
		assert.True(t, ok, "JWK with \"kty\" of \"RSA\" should have \"d\" parameter (private exponent)")
		// Check that size of `d` is the correct size
		bytes, err := base64.RawURLEncoding.DecodeString(d.(string))
		assert.FatalError(t, err)
		if v, ok := j.command.flags["size"]; ok {
			size, err := strconv.Atoi(v)
			assert.FatalError(t, err)
			assert.Equals(t, len(bytes)*8, size)
		} else {
			assert.Equals(t, len(bytes)*8, 2048)
		}

		_, ok = m["p"]
		assert.True(t, ok, "JWK with \"kty\" of \"RSA\" should have \"p\" parameter (first prime factor)")
		_, ok = m["q"]
		assert.True(t, ok, "JWK with \"kty\" of \"RSA\" should have \"p\" parameter (second prime factor)")
	}
}

// TODO: Calling this on a successful test appears to cause a SEGFAULT?
func (j JWKTest) fail(t *testing.T, expected string, msg ...interface{}) {
	j.command.fail(t, j.name, expected, msg)
}

func TestCryptoJWK(t *testing.T) {
	t.Run("jwk", func(t *testing.T) {
		NewJWKTest("default").test(t)
		t.Run("kty=RSA", func(t *testing.T) {
			NewJWKTest("RSA-2048-RS256").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "RS256").test(t)
			NewJWKTest("RSA-2048-RS384").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "RS384").test(t)
			NewJWKTest("RSA-2048-RS512").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "RS512").test(t)
			NewJWKTest("RSA-4096-RS256").setFlag("kty", "RSA").setFlag("size", "4096").setFlag("alg", "RS256").test(t)
			NewJWKTest("RSA-2048-PS256").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "PS256").test(t)
			NewJWKTest("RSA-2048-PS384").setFlag("type", "RSA").setFlag("size", "2048").setFlag("alg", "PS384").test(t)
			NewJWKTest("RSA-2048-PS512").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "PS512").test(t)
			NewJWKTest("RSA-1024-PS256-fail").setFlag("kty", "RSA").setFlag("size", "1024").setFlag("alg", "PS512").fail(t, "flag '--size' requires at least 2048 unless '--insecure' flag is provided\n")
			NewJWKTest("RSA-1024-PS256").setFlag("type", "RSA").setFlag("size", "1024").setFlag("alg", "PS512").setFlag("insecure", "").test(t)
			NewJWKTest("RSA-16-PS256").setFlag("kty", "RSA").setFlag("size", "16").setFlag("alg", "PS512").setFlag("insecure", "").test(t)
			// Broken - actual size is 16. Needs to be multiple of 8?
			//NewJWKTest("RSA-12-PS256").setFlag("kty", "RSA").setFlag("size", "12").setFlag("alg", "PS512").setFlag("insecure", "").test(t)
			// Broken - fails in crypto/rsa
			//NewJWKTest("RSA-11-PS256").setFlag("kty", "RSA").setFlag("size", "11").setFlag("alg", "PS512").setFlag("insecure", "").test(t)
			//NewJWKTest("RSA-0-PS256").setFlag("kty", "RSA").setFlag("size", "0").setFlag("alg", "PS512").setFlag("insecure", "").test(t)
			NewJWKTest("RSA-0-PS256").setFlag("kty", "RSA").setFlag("size", "-1").setFlag("alg", "PS512").setFlag("insecure", "").fail(t, "flag '--size' must be greater or equal than 0\n")
			NewJWKTest("RSA-2048-PS256-enc-bad-alg").setFlag("type", "RSA").setFlag("size", "2048").setFlag("alg", "PS256").setFlag("use", "enc").fail(t, "alg 'PS256' is not compatible with kty 'RSA'\n")
			NewJWKTest("RSA-2048-A128KW-enc-bad-alg").setFlag("type", "RSA").setFlag("size", "2048").setFlag("alg", "A128KW").setFlag("use", "enc").fail(t, "alg 'A128KW' is not compatible with kty 'RSA'\n")
			NewJWKTest("RSA-2048-RSAOAEP-enc").setFlag("type", "RSA").setFlag("size", "2048").setFlag("alg", "RSA-OAEP").setFlag("use", "enc").test(t)
			NewJWKTest("RSA-2048-RSAOAEP256-enc").setFlag("kty", "RSA").setFlag("size", "2056").setFlag("alg", "RSA-OAEP-256").setFlag("use", "enc").test(t)
			NewJWKTest("RSA-2048-RSA1_5-enc").setFlag("type", "RSA").setFlag("size", "2064").setFlag("alg", "RSA1_5").setFlag("use", "enc").test(t)
			NewJWKTest("RSA-2048-PS512-kid-snarf").setFlag("kty", "RSA").setFlag("size", "2064").setFlag("alg", "PS512").setFlag("kid", "snarf").test(t)
			NewJWKTest("RSA-default").setFlag("kty", "RSA").test(t)
			NewJWKTest("alg=ES256").setFlag("kty", "RSA").setFlag("alg", "ES256").setFlag("size", "2048").fail(t, "alg 'ES256' is not compatible with kty 'RSA'\n")
			NewJWKTest("alg=HS384").setFlag("type", "RSA").setFlag("alg", "HS384").setFlag("size", "2048").fail(t, "alg 'HS384' is not compatible with kty 'RSA'\n")
			NewJWKTest("RSA-2048-PS256-crv").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "PS256").setFlag("crv", "P-521").fail(t, "flag '--crv' is incompatible with '--kty RSA'\n")
			NewJWKTest("RSA-128-PS256").setFlag("kty", "RSA").setFlag("size", "128").setFlag("alg", "PS256").fail(t, "flag '--size' requires at least 2048 unless '--insecure' flag is provided\n")
			NewJWKTest("rsa").setFlag("kty", "rsa").fail(t, "invalid value 'rsa' for flag '--kty'; options are EC, RSA, OKP, or oct\n")
			NewJWKTest("RSA-nopass-fail").setFlag("kty", "RSA").setFlag("no-password", "").fail(t, "flag '--no-password' requires the '--insecure' flag\n")
			NewJWKTest("RSA-nopass").setFlag("kty", "RSA").setFlag("no-password", "").setFlag("insecure", "").test(t)
		})
		t.Run("kty=oct", func(t *testing.T) {
			NewJWKTest("oct-default").setFlag("kty", "oct").test(t)
			NewJWKTest("oct-32-fail").setFlag("type", "oct").setFlag("size", "4").fail(t, "flag '--size' requires at least 16 unless '--insecure' flag is provided\n")
			NewJWKTest("oct-32").setFlag("kty", "oct").setFlag("size", "4").setFlag("insecure", "").test(t)
			NewJWKTest("oct-16").setFlag("kty", "oct").setFlag("size", "2").setFlag("insecure", "").test(t)
			NewJWKTest("oct-0").setFlag("kty", "oct").setFlag("size", "0").setFlag("insecure", "").fail(t, "flag '--size' must be greater or equal than 0\n")
			NewJWKTest("oct-512-HS256").setFlag("type", "oct").setFlag("alg", "HS256").setFlag("size", "64").test(t)
			NewJWKTest("oct-512-HS384").setFlag("kty", "oct").setFlag("alg", "HS384").setFlag("size", "64").test(t)
			NewJWKTest("oct-512-HS512").setFlag("kty", "oct").setFlag("alg", "HS512").setFlag("size", "64").test(t)
			NewJWKTest("oct-256-HS256-enc").setFlag("kty", "oct").setFlag("alg", "HS256").setFlag("size", "32").setFlag("use", "enc").fail(t, "alg 'HS256' is not compatible with kty 'oct'\n")
			NewJWKTest("oct-256-dir-enc").setFlag("kty", "oct").setFlag("alg", "dir").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-A128KW-enc").setFlag("kty", "oct").setFlag("alg", "A128KW").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-A192KW-enc").setFlag("kty", "oct").setFlag("alg", "A192KW").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-A256KW-enc").setFlag("kty", "oct").setFlag("alg", "A256KW").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-A128GCMKW-enc").setFlag("kty", "oct").setFlag("alg", "A128GCMKW").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-A192GCMKW-enc").setFlag("kty", "oct").setFlag("alg", "A192GCMKW").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-A256GCMKW-enc").setFlag("kty", "oct").setFlag("alg", "A256GCMKW").setFlag("size", "32").setFlag("use", "enc").test(t)
			NewJWKTest("oct-256-HS256-kid-foo").setFlag("kty", "oct").setFlag("alg", "HS256").setFlag("size", "32").setFlag("kid", "foo").test(t)
			NewJWKTest("alg=RS256").setFlag("kty", "oct").setFlag("alg", "RS256").setFlag("size", "64").fail(t, "alg 'RS256' is not compatible with kty 'oct'\n")
			NewJWKTest("oct-512-HS256-crv").setFlag("kty", "oct").setFlag("alg", "HS256").setFlag("size", "64").setFlag("crv", "P-256").fail(t, "flag '--crv' is incompatible with '--kty oct'\n")
			NewJWKTest("OCT").setFlag("kty", "OCT").fail(t, "invalid value 'OCT' for flag '--kty'; options are EC, RSA, OKP, or oct\n")
		})
		t.Run("kty=EC", func(t *testing.T) {
			NewJWKTest("EC-default").setFlag("kty", "EC").test(t)
			NewJWKTest("EC-kid-w00t").setFlag("kty", "EC").setFlag("kid", "w00t").test(t)
			NewJWKTest("EC-P256-ES256").setFlag("kty", "EC").setFlag("crv", "P-256").setFlag("alg", "ES256").test(t)
			NewJWKTest("EC-P384-ES384").setFlag("type", "EC").setFlag("crv", "P-384").setFlag("alg", "ES384").test(t)
			NewJWKTest("EC-P521-ES512").setFlag("kty", "EC").setFlag("crv", "P-521").setFlag("alg", "ES512").test(t)
			NewJWKTest("EC-P521-RSA1_5-enc").setFlag("kty", "EC").setFlag("crv", "P-521").setFlag("alg", "RSA1_5").setFlag("use", "enc").fail(t, "alg 'RSA1_5' is not compatible with kty 'EC'\n")
			NewJWKTest("EC-P521-ECDHES-enc").setFlag("kty", "EC").setFlag("crv", "P-521").setFlag("alg", "ECDH-ES").setFlag("use", "enc").test(t)
			NewJWKTest("EC-P521-ECDHESA128KW-enc").setFlag("kty", "EC").setFlag("crv", "P-521").setFlag("alg", "ECDH-ES+A128KW").setFlag("use", "enc").test(t)
			NewJWKTest("EC-P521-ECDHESA192KW-enc").setFlag("kty", "EC").setFlag("crv", "P-521").setFlag("alg", "ECDH-ES+A192KW").setFlag("use", "enc").test(t)
			NewJWKTest("EC-P521-ECDHESA256KW-enc").setFlag("kty", "EC").setFlag("crv", "P-521").setFlag("alg", "ECDH-ES+A256KW").setFlag("use", "enc").test(t)
			NewJWKTest("EC-P256-ES384").setFlag("type", "EC").setFlag("crv", "P-256").setFlag("alg", "ES384").fail(t, "alg 'ES384' is not compatible with kty 'EC' and crv 'P-256'\n")
			NewJWKTest("EC-P256-ES256-size").setFlag("kty", "EC").setFlag("crv", "P-256").setFlag("alg", "ES256").setFlag("size", "2048").fail(t, "flag '--size' is incompatible with '--kty EC'\n")
			NewJWKTest("EC-P256").setFlag("kty", "EC").setFlag("crv", "P-256").test(t)
			NewJWKTest("EC-P384").setFlag("kty", "EC").setFlag("crv", "P-384").test(t)
			NewJWKTest("EC-P521").setFlag("kty", "EC").setFlag("crv", "P-521").test(t)
			NewJWKTest("ec").setFlag("kty", "ec").fail(t, "invalid value 'ec' for flag '--kty'; options are EC, RSA, OKP, or oct\n")
		})
		t.Run("kty=OKP", func(t *testing.T) {
			NewJWKTest("OKP-Ed25519-default").setFlag("kty", "OKP").setFlag("crv", "Ed25519").test(t)
			NewJWKTest("OKP-Ed25519-deadbeef").setFlag("kty", "OKP").setFlag("crv", "Ed25519").setFlag("kid", "deadbeef").test(t)
			NewJWKTest("OKP-Ed25519-EdDSA").setFlag("type", "OKP").setFlag("crv", "Ed25519").setFlag("alg", "EdDSA").test(t)
			NewJWKTest("OKP-Ed25519-EdDSA").setFlag("kty", "OKP").setFlag("crv", "Ed25519").setFlag("alg", "ES256").fail(t, "alg 'ES256' is not compatible with kty 'OKP' and crv 'Ed25519'\n")
			NewJWKTest("OKP-Ed25519-EdDSA").setFlag("kty", "OKP").setFlag("crv", "Ed25519").setFlag("size", "256").fail(t, "flag '--size' is incompatible with '--kty OKP'\n")
			NewJWKTest("okp").setFlag("kty", "okp").fail(t, "invalid value 'okp' for flag '--kty'; options are EC, RSA, OKP, or oct\n")
		})
		NewJWKTest("kty=FOO").setFlag("kty", "FOO").fail(t, "invalid value 'FOO' for flag '--kty'; options are EC, RSA, OKP, or oct\n")
		NewJWKTest("kty=ec").setFlag("kty", "ec").fail(t, "invalid value 'ec' for flag '--kty'; options are EC, RSA, OKP, or oct\n", "kty flag is case-sensitive")
		NewJWKTest("alg=rs256").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "rs256").fail(t, "alg 'rs256' is not compatible with kty 'RSA'\n", "alg flag is case-sensitive")
		NewJWKTest("alg=snarf").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("alg", "snarf").fail(t, "alg 'snarf' is not compatible with kty 'RSA'\n")
		NewJWKTest("alg=rs256").setFlag("alg", "rs256").fail(t, "alg 'rs256' is not compatible with kty 'EC' and crv 'P-256'\n", "alg flag is case-sensitive")
		// Broken - prints usage
		//NewJWKTest("type-and-kty").setFlag("type", "RSA").setFlag("kty", "RSA").fail(t, "Cannot use two forms of the same flag: type kty")

		NewCLICommand().setCommand("step crypto jwk create").fail(t, "missing-args#1", "not enough positional arguments were provided in 'step crypto jwk create <public-jwk-file> <private-jwk-file>'\n")
		NewCLICommand().setCommand("step crypto jwk create").setArguments("foo.json").fail(t, "missing-args#2", "not enough positional arguments were provided in 'step crypto jwk create <public-jwk-file> <private-jwk-file>'\n")
		NewCLICommand().setCommand("step crypto jwk create").setArguments("foo.1.json foo.2.json foo.3.json").fail(t, "too-many-args", "too many positional arguments were provided in 'step crypto jwk create <public-jwk-file> <private-jwk-file>'\n")
		NewCLICommand().setCommand("step crypto jwk create").setArguments("foo.json foo.json").fail(t, "pub-priv-same", "positional arguments <public-jwk-file> and <private-jwk-file> cannot be equal in 'step crypto jwk create <public-jwk-file> <private-jwk-file>'\n")
		// Broken - prints usage
		//NewCLICommand().setCommand("step crypto jwk create").setArguments("foo.json bar.json").setFlag("size", "blort").fail(t, "non-int-size", "invalid value \"blort\" for flag -size: strconv.ParseInt: parsing \"blort\": invalid syntax")
	})
}
