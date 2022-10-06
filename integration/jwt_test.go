//go:build integration
// +build integration

package integration

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ThomasRooney/gexpect"
	"github.com/icrowley/fake"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
	jose "gopkg.in/square/go-jose.v2"
)

type JWK struct {
	pubfile  string
	prvfile  string
	password string
	ispem    bool
	iskeyset bool
}

func (j JWK) jwk() (*jose.JSONWebKey, error) {
	jwk := new(jose.JSONWebKey)
	b, err := os.ReadFile(j.prvfile)
	if err != nil {
		return nil, err
	}
	if enc, err := jose.ParseEncrypted(string(b)); err == nil {
		b, err = enc.Decrypt([]byte(j.password))
		if err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(b, jwk); err != nil {
		return nil, err
	}
	return jwk, nil
}

func (j JWK) pem() (string, error) {
	jwk, err := j.jwk()
	if err != nil {
		return "", err
	}
	b, err := pemutil.Serialize(jwk.Key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(b)), err
}

func readJSON(name string) (map[string]interface{}, error) {
	dat, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	err = json.Unmarshal(dat, &m)
	return m, err
}

type JWTSignTest struct {
	command CLICommand
	jwk     JWK
}

func NewJWTSignTest(jwk JWK) JWTSignTest {
	cmd := NewCLICommand().setCommand("step crypto jwt sign").setFlag("key", jwk.prvfile)
	return JWTSignTest{cmd, jwk}
}

func (j JWTSignTest) setFlag(key, value string) JWTSignTest {
	return JWTSignTest{j.command.setFlag(key, value), j.jwk}
}

func (j JWTSignTest) exp(d time.Duration) JWTSignTest {
	exp := time.Now().Add(d)
	return j.setFlag("exp", strconv.Itoa(int(exp.Unix())))
}

func (j JWTSignTest) nbf(d time.Duration) JWTSignTest {
	nbf := time.Now().Add(d)
	return j.setFlag("nbf", strconv.Itoa(int(nbf.Unix())))
}

func (j JWTSignTest) iat(d time.Duration) JWTSignTest {
	iat := time.Now().Add(d)
	return j.setFlag("iat", strconv.Itoa(int(iat.Unix())))
}

func (j JWTSignTest) test(t *testing.T, name string) string {
	var jwt string
	t.Run(name, func(t *testing.T) {
		// Beware. This is fragile as hell. Ugh. If the output or prompt for the
		// jwt sign subcommand changes this will need to change too.
		if j.jwk.password != "" {
			cmd, err := gexpect.Spawn(j.command.cmd())
			assert.FatalError(t, err)
			prompt := "Please enter the password to decrypt " + j.jwk.prvfile + ":"
			assert.Nil(t, cmd.ExpectTimeout(prompt, DefaultTimeout))
			assert.Nil(t, cmd.SendLine(j.jwk.password))

			var lines []string
			for {
				line, err := cmd.ReadLine()
				line = strings.Trim(line, "\r")
				if err != nil {
					break
				}
				lines = append(lines, line)
			}

			jwt = CleanOutput(strings.Trim(strings.Join(lines, "\n"), " \r\n\u2588"))
			err = cmd.Wait()
			if assert.Nil(t, err) {
				j.checkJwt(t, jwt)
			}
			if t.Failed() {
				t.Errorf("Output did not match for command `%s`", j.command.cmd())
				t.Errorf("Prompt:\n%s\n\n", prompt)
				t.Errorf("Output:\n%s\n", jwt)
			}
			cmd.Wait()
			cmd.Close()
		} else {
			out, err := j.command.run()
			assert.FatalError(t, err)
			jwt = out.stdout
			j.checkJwt(t, jwt)
		}
	})
	return jwt
}

func (j JWTSignTest) fail(t *testing.T, name, expected string) {
	if j.jwk.password != "" {
		t.Run(name, func(t *testing.T) {
			cmd, err := gexpect.Command(j.command.cmd())
			assert.FatalError(t, err)
			assert.FatalError(t, cmd.Start())
			assert.FatalError(t, cmd.ExpectTimeout("Please enter the password to decrypt "+j.jwk.prvfile+": ", DefaultTimeout))
			assert.FatalError(t, cmd.SendLine(j.jwk.password))
			_, err = cmd.ReadLine() // Prompt prints a newline
			assert.FatalError(t, err)

			var lines []string
			for {
				line, err := cmd.ReadLine()
				line = strings.Trim(line, "\r")
				if err != nil {
					break
				}
				lines = append(lines, line)
			}

			actual := CleanOutput(strings.Join(lines, "\n") + "\n")
			assert.Equals(t, expected, actual)

			err = cmd.Wait()
			if assert.NotNil(t, err) {
				assert.Equals(t, err.Error(), "exit status 1")
			}
			if t.Failed() {
				t.Errorf("Error message did not match for command `%s`", j.command.cmd())
			}
		})
	} else {
		j.command.fail(t, name, expected, "")
	}
}

func decodeB64Json(s string) (map[string]interface{}, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	m := make(map[string]interface{})
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func encodeB64Json(o interface{}) (string, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeJWT(jwt string) (map[string]interface{}, map[string]interface{}, string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, nil, "", errors.Errorf("invalid jwt; found %d parts", len(parts))
	}
	header, err := decodeB64Json(parts[0])
	if err != nil {
		return nil, nil, "", err
	}
	payload, err := decodeB64Json(parts[1])
	if err != nil {
		return nil, nil, "", err
	}

	return header, payload, strings.TrimRight(parts[2], "\n"), nil
}

func inspectJWT(jwt string) (map[string]interface{}, error) {
	out, err := NewCLICommand().setCommand(`step crypto jwt inspect --insecure`).setStdin(jwt).run()
	if err != nil {
		return nil, err
	}
	inspect := make(map[string]interface{})
	err = json.Unmarshal([]byte(out.stdout), &inspect)
	return inspect, err
}

func (j JWTSignTest) checkJwt(t *testing.T, jwt string) {
	header, payload, signature, err := decodeJWT(jwt)
	assert.FatalError(t, err, "Error:", err, "JWT:", jwt)

	inspect, err := inspectJWT(strings.Trim(jwt, " \r\n"))
	assert.FatalError(t, err)
	assert.True(t, reflect.DeepEqual(header, inspect["header"]))
	assert.True(t, reflect.DeepEqual(payload, inspect["payload"]))
	assert.Equals(t, signature, inspect["signature"])

	assert.Equals(t, "JWT", header["typ"])
	// TODO: Check that the correct alg is in the JWT
	//assert.Equals(t, "ES256", header["alg"])

	if sub, ok := j.command.flags["sub"]; ok {
		assert.Equals(t, sub, payload["sub"])
	} else {
		_, ok = payload["sub"]
		assert.False(t, ok)
	}
	if iss, ok := j.command.flags["iss"]; ok {
		assert.Equals(t, iss, payload["iss"])
	} else {
		_, ok = payload["iss"]
		assert.False(t, ok)
	}
	if jti, ok := j.command.flags["jti"]; ok {
		assert.Equals(t, jti, payload["jti"])
	} else {
		_, ok = payload["jti"]
		assert.False(t, ok)
	}

	// TODO: Check aud (may be an array)
	//assert.Equals(t, j.command.flags["aud"], payload["aud"])

	// TODO: Check additional payload claims from stdin

	if _, ok := j.command.flags["exp"]; ok {
		eexp, err := strconv.Atoi(j.command.flags["exp"])
		assert.FatalError(t, err)
		aexp := int(payload["exp"].(float64))
		assert.Equals(t, eexp, aexp)
	}

	iat := payload["iat"].(float64)
	nbf := payload["nbf"].(float64)
	now := float64(time.Now().Unix())
	assert.True(t, math.Abs(now-iat) < 10)
	assert.True(t, math.Abs(now-nbf) < 10)
	if _, ok := j.command.flags["iat"]; ok {
		eiat, err := strconv.Atoi(j.command.flags["iat"])
		assert.FatalError(t, err)
		assert.Equals(t, eiat, int(iat))
	}
	if _, ok := j.command.flags["nbf"]; ok {
		enbf, err := strconv.Atoi(j.command.flags["nbf"])
		assert.FatalError(t, err)
		assert.Equals(t, enbf, int(nbf))
	}
}

type JWTVerifyTest struct {
	command CLICommand
	jwk     JWK
}

func NewJWTVerifyTest(jwk JWK) JWTVerifyTest {
	cmd := NewCLICommand().setCommand("step crypto jwt verify").setFlag("key", jwk.pubfile)
	return JWTVerifyTest{cmd, jwk}
}

func (j JWTVerifyTest) setFlag(key, value string) JWTVerifyTest {
	return JWTVerifyTest{j.command.setFlag(key, value), j.jwk}
}

func (j JWTVerifyTest) test(t *testing.T, name, jwt string) {
	t.Run(name, func(t *testing.T) {
		out, err := j.command.setStdin(jwt).run()
		assert.FatalError(t, err, fmt.Sprintf("`%s`: returned error '%s'\n\nOutput:\n%s\n\nJWT:\n%s", j.command.cmd(), err, out.combined, jwt))
		jwt := make(map[string]interface{})
		err = json.Unmarshal([]byte(out.combined), &jwt)
		assert.FatalError(t, err)

		// TODO: Factor out some of this / combine with checkJwt above.
		header := jwt["header"].(map[string]interface{})
		payload := jwt["payload"].(map[string]interface{})
		assert.Equals(t, "JWT", header["typ"])

		// Alg in the header, cli flags, and JWK, respectively (might be nil if not set)
		halg, shalg := header["alg"]
		falg, sfalg := j.command.flags["alg"]
		kalg, skalg := func() (string, bool) {
			if j.jwk.ispem {
				return "", false
			} else if j.jwk.iskeyset {
				jwks, err := readJSON(j.jwk.pubfile)
				assert.FatalError(t, err)
				for _, e := range jwks["keys"].([]interface{}) {
					jwk := e.(map[string]interface{})
					if jwk["kid"].(string) == j.command.flags["kid"] {
						kalg, skalg := jwk["alg"]
						return kalg.(string), skalg
					}
				}
				return "", false
			} else {
				jwk, err := readJSON(j.jwk.pubfile)
				assert.FatalError(t, err)
				kalg, skalg := jwk["alg"]
				return kalg.(string), skalg
			}
		}()
		if sfalg {
			if shalg {
				assert.Equals(t, falg, halg)
			}
			if skalg {
				assert.Equals(t, falg, kalg)
			}
		}
		if shalg && skalg {
			assert.Equals(t, halg, kalg)
		}

		if iss, ok := j.command.flags["iss"]; ok {
			assert.Equals(t, iss, payload["iss"])
		} else {
			_, ok = j.command.flags["subtle"]
			assert.True(t, ok)
		}

		if aud, ok := j.command.flags["aud"]; ok {
			auds, ok := payload["aud"]
			if ok {
				switch auds := auds.(type) {
				case string:
					assert.Equals(t, aud, auds)
				case []interface{}:
					/*
						TODO: This.
						if len(auds) == 1 {
							t.Errorf(`single "aud" in JWT should be string not array`)
						}
					*/
					found := false
					for _, a := range auds {
						found = (a.(string) == aud)
					}
					assert.True(t, found)
				default:
					t.Errorf("unexpected type for aud: %T", auds)
				}
			} else {
				t.Error(`no "aud" property in JWT`)
			}
		}

		iat, hiat := payload["iat"]
		nbf, hnbf := payload["nbf"]
		exp, hexp := payload["exp"]
		now := float64(time.Now().Unix())
		if hiat {
			assert.True(t, math.Abs(now-iat.(float64)) < 10)
		}
		if hnbf && nbf.(float64) != 0 {
			assert.True(t, math.Abs(now-nbf.(float64)) < 10)
		}
		_, noExp := j.command.flags["no-exp-check"]
		_, insecure := j.command.flags["insecure"]
		if hexp && !(noExp && insecure) {
			assert.True(t, exp.(float64) > now)
		}
	})
}

func (j JWTVerifyTest) fail(t *testing.T, name string, jwt string, expected interface{}) {
	j.command.setStdin(jwt).fail(t, name, expected, "")
}

type JWTTest struct {
	sign   JWTSignTest
	verify JWTVerifyTest
}

func NewJWTTest(jwk JWK) JWTTest {
	return JWTTest{NewJWTSignTest(jwk), NewJWTVerifyTest(jwk)}
}

func (j JWTTest) setFlag(key, value string) JWTTest {
	return j.setSFlag(key, value).setVFlag(key, value)
}

func (j JWTTest) setSFlag(key, value string) JWTTest {
	return JWTTest{j.sign.setFlag(key, value), j.verify}
}

func (j JWTTest) exp(d time.Duration) JWTTest {
	return JWTTest{j.sign.exp(d), j.verify}
}

func (j JWTTest) nbf(d time.Duration) JWTTest {
	return JWTTest{j.sign.nbf(d), j.verify}
}

func (j JWTTest) iat(d time.Duration) JWTTest {
	return JWTTest{j.sign.iat(d), j.verify}
}

func (j JWTTest) setVFlag(key, value string) JWTTest {
	return JWTTest{j.sign, j.verify.setFlag(key, value)}
}

func (j JWTTest) test(t *testing.T, name string) {
	t.Run(name, func(t *testing.T) {
		jwt := j.sign.test(t, "sign")
		j.verify.test(t, "verify", jwt)
		if t.Failed() {
			fmt.Printf("Commands:\n\t%s\n\t%s\n", j.sign.command.cmd(), j.verify.command.cmd())
		}
	})
}

var rsrc csrc
var r = rand.New(rsrc)

type csrc struct{}

func (s csrc) Seed(seed int64) {}
func (s csrc) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}
func (s csrc) Uint64() (v uint64) {
	err := binary.Read(crand.Reader, binary.BigEndian, &v)
	if err != nil {
		panic(err)
	}
	return v
}

func FakeURL() string {
	scheme := []string{"http", "https"}[r.Intn(2)]
	domain := fake.DomainName()
	n := r.Intn(5)
	path := make([]string, n)
	for i := 0; i < n; i++ {
		path[i] = fake.Word()
	}
	return scheme + "://" + domain + "/" + strings.Join(path, "/")
}

// A principal is usually a name, URL, or email address.
func FakePrincipal() string {
	return []string{fake.EmailAddress(), FakeURL(), fake.FullName()}[r.Intn(3)]
}

func randid() string {
	b := make([]byte, 10)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func NewJWK(kty string, t *testing.T) JWK {
	jwk := NewJWKTest(fmt.Sprintf("jwt-jwk-%s", kty))
	jwk = jwk.setFlag("kty", kty).setFlag("kid", randid())
	if kty == "OKP" {
		jwk = jwk.setFlag("crv", "Ed25519")
	}
	return JWKFromTest(t, jwk)
}

func JWKFromTest(t *testing.T, jt JWKTest) JWK {
	_, password := jt.test(t)
	return JWK{jt.pubfile, jt.prvfile, password, false, false}
}

func TestCryptoJWT(t *testing.T) {
	// Generate some JWKs that we can use for testing.
	jwkec := NewJWK("EC", t)
	jwkrsa := NewJWK("RSA", t)
	jwkoct := NewJWK("oct", t)
	jwkokp := NewJWK("OKP", t)
	jwknopass := JWKFromTest(t, NewJWKTest("jwt-jwk-nopass").setFlag("kty", "EC").setFlag("no-password", "").setFlag("insecure", ""))

	t.Run("jwt", func(t *testing.T) {
		mkjwt := func(jwk JWK) JWTTest {
			// Audience, issuer, and subject can be emails, URLs, or any other string.
			aud := FakePrincipal()
			iss := FakePrincipal()
			sub := FakePrincipal()
			return NewJWTTest(jwk).setFlag("aud", aud).setFlag("iss", iss).setSFlag("sub", sub).exp(1 * time.Minute)
		}
		mkjwt(jwkec).test(t, "jwt-ec")
		mkjwt(jwkrsa).test(t, "jwt-rsa")
		mkjwt(jwkoct).test(t, "jwt-oct")
		mkjwt(jwkokp).test(t, "jwt-okp")
		mkjwt(jwknopass).test(t, "jwt-nopass")

		t.Run("sign", func(t *testing.T) {
			jwtrsa := mkjwt(jwkrsa).sign
			jwtrsa.setFlag("alg", "RS384").fail(t, "wrong-alg", "alg RS384 does not match the alg on testdata-tmp/jwt-jwk-RSA-prv.json\n")

			mkjwt(JWKFromTest(t, NewJWKTest("jwt-jwk-enc").setFlag("use", "enc").setFlag("no-password", "").setFlag("insecure", ""))).sign.fail(t, "use-enc", "invalid jwk use: found 'enc', expecting 'sig' (signature)\n")

			subtle := NewJWTTest(jwkrsa).sign
			subtle.fail(t, "no-aud-iss-sub-exp", "flag '--iss' is required unless '--subtle' is used\n")
			subtle.setFlag("sub", FakePrincipal()).setFlag("iss", FakePrincipal()).exp(1*time.Minute).fail(t, "no-aud", "flag '--aud' is required unless '--subtle' is used\n")
			subtle.setFlag("sub", FakePrincipal()).setFlag("aud", FakePrincipal()).exp(1*time.Minute).fail(t, "no-iss", "flag '--iss' is required unless '--subtle' is used\n")
			subtle.setFlag("aud", FakePrincipal()).setFlag("iss", FakePrincipal()).exp(1*time.Minute).fail(t, "no-sub", "flag '--sub' is required unless '--subtle' is used\n")
			subtle.setFlag("sub", FakePrincipal()).setFlag("aud", FakePrincipal()).setFlag("iss", FakePrincipal()).fail(t, "no-exp", "flag '--exp' is required unless '--subtle' is used\n")
			subtle = subtle.setFlag("subtle", "")
			subtle.test(t, "no-aud-iss-sub-exp-subtle")
			subtle.setFlag("sub", FakePrincipal()).setFlag("iss", FakePrincipal()).exp(1*time.Minute).test(t, "no-aud-subtle")
			subtle.setFlag("sub", FakePrincipal()).setFlag("aud", FakePrincipal()).exp(1*time.Minute).test(t, "no-iss-subtle")
			subtle.setFlag("aud", FakePrincipal()).setFlag("iss", FakePrincipal()).exp(1*time.Minute).test(t, "no-sub-subtle")
			subtle.setFlag("sub", FakePrincipal()).setFlag("aud", FakePrincipal()).setFlag("iss", FakePrincipal()).test(t, "no-exp-subtle")

			nouse := mkjwt(JWK{"testdata/jwk-no-use.pub.json", "testdata/jwk-no-use.json", "", false, false})
			nouse.test(t, "no-use")
			noalg := mkjwt(JWK{"testdata/jwk-no-alg.pub.json", "testdata/jwk-no-alg.json", "", false, false})
			noalg.sign.test(t, "no-alg")

			mkjwt(JWK{"foo", "foo", "", false, false}).sign.fail(t, "missing-key-file", "error reading foo: open foo: no such file or directory\n")
			mkjwt(JWK{"testdata/bad-key.pub.json", "testdata/bad-key.json", "", false, false}).sign.fail(t, "bad-key-file", "error reading testdata/bad-key.json: unsupported format\n")
			mkjwt(JWK{"testdata/bad-key.pub.json", "testdata/bad-key.json", "", true, false}).sign.fail(t, "bad-key-file-pem", "error reading testdata/bad-key.json: unsupported format\n")
			mkjwt(JWK{"testdata/jwk-pGoLJDgF5fgTNnB47SKMnVUzVNdu6MF0.pub.json", "testdata/jwk-pGoLJDgF5fgTNnB47SKMnVUzVNdu6MF0.pub.json", "", false, false}).sign.fail(t, "sign-with-pubkey", "cannot use a public key for signing\n")
			mkjwt(JWK{"testdata/p256.pem.pub", "testdata/p256.pem.pub", "", true, false}).sign.fail(t, "sign-with-pubkey-pem", "cannot use a public key for signing\n")
			mkjwt(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).sign.test(t, "sign-with-rsa-default")
			mkjwt(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).sign.setFlag("alg", "RS256").test(t, "pem-alg-required")
			mkjwt(JWK{"testdata/rsa2048.pub", "testdata/twopems.pem", "", true, false}).sign.setFlag("alg", "RS256").fail(t, "multiple-keys", "error decoding testdata/twopems.pem: contains more than one key\n")
			mkjwt(JWK{"testdata/rsa2048.pub", "testdata/badheader.pem", "", true, false}).sign.setFlag("alg", "RS256").fail(t, "multiple-keys", "error decoding testdata/badheader.pem: contains an unexpected header 'FOO PRIVATE KEY'\n")
			mkjwt(JWK{"testdata/es256-enc.pub", "testdata/es256-enc.pem", "password", true, false}).sign.setFlag("alg", "ES256").test(t, "pem-encrypted")
			mkjwt(JWK{"testdata/es256-enc.pub", "testdata/es256-enc.pem", "password", true, false}).sign.setFlag("alg", "RS256").fail(t, "pem-bad-alg", "alg 'RS256' is not compatible with kty 'EC' and crv 'P-256'\n")

			fmt.Println(mkjwt(jwkrsa).exp(-1 * time.Minute).sign.command.cmd())
			mkjwt(jwkrsa).exp(-1*time.Minute).sign.fail(t, "exp-in-past", "flag '--exp' must be in the future unless the '--subtle' flag is provided\n")
			mkjwt(jwkrsa).exp(-1*time.Minute).setFlag("subtle", "").sign.test(t, "exp-in-past-subtle")

			mkjwt(jwkrsa).setSFlag("jti", "foo").test(t, "jti")

			keyset := JWTSignTest{NewCLICommand().setCommand("step crypto jwt sign").setFlag("jwks", "testdata/jwks.json"), JWK{"testdata/jwks.pub.json", "testdata/jwks.json", "", false, true}}
			keyset = keyset.setFlag("aud", FakePrincipal()).setFlag("iss", FakePrincipal()).setFlag("sub", FakePrincipal()).exp(1 * time.Minute)
			keyset.fail(t, "keyset-no-kid", "flag '--kid' requires the '--jwks' flag\n")
			keyset.setFlag("kid", "1").test(t, "keyset-kid1")
			keyset.setFlag("kid", "2").test(t, "keyset-kid2")
			keyset.setFlag("kid", "3").fail(t, "keyset-kid3", "invalid jwk use: found 'enc', expecting 'sig' (signature)\n")
			keyset.setFlag("kid", "4").fail(t, "keyset-kid4", "cannot find key with kid 4 on testdata/jwks.json\n")
			keyset.setFlag("kid", "1").setFlag("key", "foo").fail(t, "keyset-and-key", "flag '--key' and flag '--jwks' are mutually exclusive\n")
			keyset.setFlag("jwks", "foo").setFlag("kid", "1").fail(t, "nonexistent-keyset", "error reading foo: open foo: no such file or directory\n")
			keyset.setFlag("jwks", "testdata/rsa2048.pem").setFlag("kid", "1").fail(t, "bad-keyset", "error reading testdata/rsa2048.pem: unsupported format\n")
		})

		t.Run("verify", func(t *testing.T) {
			setHeader := func(jwt string, hdr string, val interface{}) string {
				parts := strings.Split(jwt, ".")
				if len(parts) != 3 {
					assert.FatalError(t, errors.Errorf("invalid jwt; found %d parts", len(parts)))
				}
				header, err := decodeB64Json(parts[0])
				if err != nil {
					assert.FatalError(t, err)
				}
				header[hdr] = val
				parts[0], err = encodeB64Json(header)
				if err != nil {
					assert.FatalError(t, err)
				}
				return strings.Join(parts, ".")
			}

			tst := mkjwt(jwkokp)
			jwt := tst.sign.test(t, "sign")
			tst.verify.fail(t, "wrong-signature", jwt[:len(jwt)-5]+"12345", "validation failed: invalid signature\n")
			tst.verify.setFlag("iss", "wrong issuer").fail(t, "iss-mismatch", jwt, "validation failed: invalid issuer claim (iss)\n")
			tst.verify.setFlag("aud", "wrong audience").fail(t, "aud-mismatch", jwt, "validation failed: invalid audience claim (aud)\n")
			tst.verify.fail(t, "crit-header", setHeader(jwt, "crit", []string{"exp"}), "validation failed: unrecognized critical headers (crit)\n")
			tst.verify.fail(t, "invalid-jwt", "asdf", "error parsing token: compact JWS format must have three parts\n")
			tst.verify.fail(t, "invalid-jwt-parts", "foo.bar.deadbeef", "error parsing token: invalid character '~' looking for beginning of value\n")

			fakejwt := func(header, payload, signature string) string {
				header = base64.RawURLEncoding.EncodeToString([]byte(header))
				payload = base64.RawURLEncoding.EncodeToString([]byte(payload))
				return strings.Join([]string{header, payload, signature}, ".")
			}
			parts := strings.Split(jwt, ".")
			tst.verify.fail(t, "invalid-jwt-header", fakejwt("foo", parts[1], parts[2]), "error parsing token: invalid character 'o' in literal false (expecting 'a')\n")
			tst.verify.fail(t, "invalid-jwt-header-json", fakejwt("[42]", "bar", "deadbeef"), "error parsing token: json: cannot unmarshal array into Go value of type jose.rawHeader\n")
			tst.verify.fail(t, "invalid-jwt-header-changed-attrib", fakejwt(`{"kty":"EC","alg":"ES256","xxx":"yyy"}`, parts[1], parts[2]), "validation failed: invalid signature\n")
			tst.verify.fail(t, "invalid-jwt-header-bad-json", fakejwt(`{"kty":"EC","alg":"ES256","}`, parts[1], parts[2]), "error parsing token: unexpected end of JSON input\n")
			tst.verify.fail(t, "invalid-jwt-payload", fakejwt(parts[0], "foo", parts[2]), "error parsing token: invalid character 'e' looking for beginning of value\n")

			subtle := NewJWTTest(jwkokp).exp(1 * time.Minute).verify
			subtle.fail(t, "no-aud-iss", jwt, "flag '--iss' is required unless the '--subtle' flag is provided\n")
			subtle.setFlag("iss", tst.verify.command.flags["iss"]).fail(t, "no-aud", jwt, "flag '--aud' is required unless the '--subtle' flag is provided\n")
			subtle.setFlag("aud", tst.verify.command.flags["aud"]).fail(t, "no-iss", jwt, "flag '--iss' is required unless the '--subtle' flag is provided\n")
			subtle = subtle.setFlag("subtle", "")
			subtle.test(t, "no-aud-iss-subtle", jwt)
			subtle.setFlag("iss", tst.verify.command.flags["iss"]).test(t, "no-aud-subtle", jwt)
			subtle.setFlag("aud", tst.verify.command.flags["aud"]).test(t, "no-iss-subtle", jwt)

			t.Run("keyset", func(t *testing.T) {
				aud := FakePrincipal()
				sub := FakePrincipal()
				iss := FakePrincipal()
				jwt = JWTSignTest{NewCLICommand().setCommand("step crypto jwt sign").setFlag("jwks", "testdata/jwks.json"), JWK{"testdata/jwks.pub.json", "testdata/jwks.json", "", false, true}}.setFlag("kid", "1").setFlag("aud", aud).setFlag("iss", iss).setFlag("sub", sub).exp(1*time.Minute).test(t, "keyset-sign")
				keyset := JWTVerifyTest{NewCLICommand().setCommand("step crypto jwt verify").setFlag("jwks", "testdata/jwks.pub.json"), JWK{"testdata/jwks.pub.json", "testdata/jwks.json", "", false, true}}.setFlag("aud", aud).setFlag("iss", iss)
				keyset.setFlag("kid", "1").test(t, "keyset", jwt)
				keyset.setFlag("kid", "2").fail(t, "wrong-kid", jwt, "validation failed: invalid signature\n")
				keyset.setFlag("kid", "4").fail(t, "kid-not-found", jwt, "cannot find key with kid 4 on testdata/jwks.pub.json\n")
				// "kid" should be optional if it's in the JWT, else required
				keyset.test(t, "kid-in-jwt", jwt)
				jwt = mkjwt(JWK{"testdata/jwks-key1.json", "testdata/jwks-key1.json", "", false, false}).sign.setFlag("aud", aud).setFlag("iss", iss).setFlag("sub", sub).setFlag("no-kid", "").exp(1*time.Minute).test(t, "keyset-key1")
				keyset.fail(t, "no-kid-in-jwt", jwt, "flag '--kid' requires the '--jwks' flag\n")
			})

			// JWK without `alg` should require --alg flag
			mkossljwt := func(t *testing.T, header, payload, key string) string {
				cmd := fmt.Sprintf("./openssl-jwt.sh -a RS256 -k %s '%s' '%s'", key, header, payload)
				jwt, err := exec.Command("bash", "-c", cmd).CombinedOutput()
				assert.FatalError(t, err)
				return string(jwt)
			}
			t.Run("pem", func(t *testing.T) {
				exp := time.Now().Add(1 * time.Minute)
				jwt = mkossljwt(t, `{"typ": "JWT", "alg": "RS256"}`, fmt.Sprintf(`{"iss": "foo", "aud": "bar", "exp": %d}`, exp.Unix()), "testdata/rsa2048.pem")
				vtst := NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false})
				vtst.setFlag("iss", "foo").setFlag("aud", "bar").fail(t, "no-alg", jwt, "flag '--alg' is required with the given key\n")
				vtst.setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS256").test(t, "verify", jwt)
				vtst.setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS384").fail(t, "alg-mismatch", jwt, "alg RS384 does not match the alg on JWT (RS256)\n")
				jwt = mkossljwt(t, `{"typ": "JWT", "alg": "RS384"}`, `{"iss": "foo", "aud": "bar"}`, "testdata/rsa2048.pem")
				vtst.setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS384").fail(t, "wrong-alg", jwt, "validation failed: invalid signature\n")
				vtst.setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS256").fail(t, "wrong-alg-mismatch", jwt, "alg RS256 does not match the alg on JWT (RS384)\n")
			})
			expiredZero := mkossljwt(t, `{"typ": "JWT", "alg": "RS256"}`, `{"exp": 0}`, "testdata/rsa2048.pem")
			NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("subtle", "").setFlag("alg", "RS256").fail(t, "expired-zero", expiredZero, regexp.MustCompile(`^validation failed: token is expired by (\d+h\d+m\d+\.\d+s) \(exp\)\n`))
			expired := mkossljwt(t, `{"typ": "JWT", "alg": "RS256"}`, `{"exp": 12345}`, "testdata/rsa2048.pem")
			NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("subtle", "").setFlag("alg", "RS256").fail(t, "expired", expired, regexp.MustCompile(`^validation failed: token is expired by (\d+h\d+m\d+\.\d+s) \(exp\)\n`))
			NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("subtle", "").setFlag("alg", "RS256").setFlag("no-exp-check", "").fail(t, "no-exp-fail", expired, "flag '--no-exp-check' requires the '--insecure' flag\n")
			NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("subtle", "").setFlag("alg", "RS256").setFlag("no-exp-check", "").setFlag("insecure", "").test(t, "no-exp-check", expired)
			noexp := mkossljwt(t, `{"typ": "JWT", "alg": "RS256"}`, `{"iss": "foo", "aud": "bar"}`, "testdata/rsa2048.pem")
			NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS256").test(t, "no-exp", noexp)
			notBeforeZero := mkossljwt(t, `{"typ": "JWT", "alg": "RS256"}`, `{"iss": "foo", "aud": "bar", "nbf": 0}`, "testdata/rsa2048.pem")
			NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS256").test(t, "not-before-zero", notBeforeZero)
			texp := NewJWTTest(jwkrsa).setSFlag("sub", FakePrincipal()).setFlag("aud", FakePrincipal()).setFlag("iss", FakePrincipal())
			jwt = texp.sign.setFlag("subtle", "").test(t, "no-exp-sign")
			texp.verify.test(t, "no-exp-verify", jwt)
			texp.verify.setFlag("no-exp-check", "").setFlag("insecure", "").test(t, "empty-exp-in-jwt", jwt)
			texp.verify.setFlag("subtle", "").test(t, "no-exp-verify-subtle", jwt)

			// Can't serialize OKP (Ed25519) keys yet. Switch to using RSA.
			tst = mkjwt(jwkrsa)
			pem, err := tst.verify.jwk.pem()
			assert.FatalError(t, err)
			jwt = mkossljwt(t, `{"typ": "JWT", "alg": "RS384"}`, `{"iss": "foo", "sub": "bar"}`, fmt.Sprintf("<(echo -en %q)", pem))
			tst.verify.setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS384").fail(t, "wrong-alg", jwt, "alg RS384 does not match the alg on testdata-tmp/jwt-jwk-RSA-pub.json\n")

			// We don't currently support JSON Serialization, Flattened JSON Serialization, or multiple signatures
			// TODO: Right now these are parse failures. They should probably parse correctly and give more helpful error messages.
			vtst := NewJWTVerifyTest(JWK{"testdata/rsa2048.pub", "testdata/rsa2048.pem", "", true, false}).setFlag("iss", "foo").setFlag("aud", "bar").setFlag("alg", "RS256")
			jwtb, _ := os.ReadFile("testdata/jwt-json-serialization.json")
			vtst.fail(t, "json-serialization", string(jwtb), "error parsing token: unexpected end of JSON input\n")
			jwtb, _ = os.ReadFile("testdata/jwt-json-serialization-flattened.json")
			vtst.fail(t, "json-serialization-flattened", string(jwtb), "error parsing token: unexpected end of JSON input\n")
			jwtb, _ = os.ReadFile("testdata/jwt-json-serialization-multi.json")
			vtst.fail(t, "json-serialization-multi", string(jwtb), "error parsing token: unexpected end of JSON input\n")
		})

		// Should fail (token not yet valid)
		t.Run("timestamps", func(t *testing.T) {
			t.Parallel()
			var extraTime = 5 * time.Second
			mkjwt(jwkrsa).iat(1*time.Second).test(t, "iat")
			t.Run("nbf", func(t *testing.T) {
				tst := mkjwt(jwkec)
				jwt := tst.nbf(extraTime).sign.test(t, "sign")
				tst.verify.fail(t, "verify-too-soon", jwt, "validation failed: token not valid yet (nbf)\n")
				time.Sleep(extraTime)
				tst.verify.test(t, "verify-succeed", jwt)
				if t.Failed() {
					t.Logf("jwt: %s", jwt)
				}
			})
			t.Run("exp", func(t *testing.T) {
				tst := mkjwt(jwkec).exp(extraTime)
				jwt := tst.sign.test(t, "sign")
				tst.verify.test(t, "verify-succeed", jwt)
				time.Sleep(extraTime)
				tst.verify.fail(t, "verify-expired", jwt, regexp.MustCompile(`^validation failed: token is expired by (\d\d\dms|\d\.\d+s) \(exp\)\n`))
				if t.Failed() {
					t.Logf("jwt: %s", jwt)
				}
			})
		})

		t.Run("wrong-pass", func(t *testing.T) {
			tst := mkjwt(jwkrsa).setFlag("aud", "a").setFlag("iss", "i").setSFlag("sub", "s").exp(1 * time.Minute)
			cmd, err := gexpect.Spawn(tst.sign.command.cmd())
			assert.FatalError(t, err)
			prompt := "Please enter the password to decrypt " + tst.sign.jwk.prvfile + ": "
			for i := 0; i < 3; i++ {
				assert.FatalError(t, cmd.ExpectTimeout(prompt, DefaultTimeout))
				assert.FatalError(t, cmd.SendLine("foo"))
				time.Sleep(1 * time.Second)
			}
			assert.FatalError(t, cmd.ExpectTimeout("failed to decrypt JWK: invalid password", DefaultTimeout))
		})

		t.Run("inspect", func(t *testing.T) {
			NewCLICommand().setCommand(`echo "foo" | step crypto jwt inspect`).fail(t, "requires-insecure", "'step crypto jwt inspect' requires the '--insecure' flag\n", "")
		})
	})
}
