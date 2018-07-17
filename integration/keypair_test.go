// +build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/ThomasRooney/gexpect"
	"github.com/smallstep/assert"
)

type KeypairCmd struct {
	name     string
	command  CLICommand
	pubfile  string
	prvfile  string
	password string
}

func (k KeypairCmd) setFlag(key, value string) KeypairCmd {
	return KeypairCmd{k.name, k.command.setFlag(key, value), k.pubfile, k.prvfile, k.password}
}

func (k KeypairCmd) setPassword(password string) KeypairCmd {
	return KeypairCmd{k.name, k.command, k.pubfile, k.prvfile, password}
}

func (k KeypairCmd) testJwtSignVerify(t *testing.T) {
	aud := FakePrincipal()
	iss := FakePrincipal()
	sub := FakePrincipal()
	jwk := JWK{k.pubfile, k.prvfile, k.password, true, false}
	test := NewJWTTest(jwk).setFlag("aud", aud).setFlag("iss", iss).setSFlag("sub", sub).exp(1 * time.Minute)
	if k.command.flags["type"] == "RSA" {
		test = test.setFlag("alg", "RS256")
	}
	test.test(t, fmt.Sprintf("%s-jwt-sign-verify", k.name))
}

func (k KeypairCmd) test(t *testing.T) {
	t.Run(k.name, func(t *testing.T) {
		cmd, err := gexpect.Spawn(k.command.cmd())
		assert.FatalError(t, err)
		prompt := fmt.Sprintf("Password with which to encrypt private key file `%s`: ", k.prvfile)
		assert.FatalError(t, cmd.ExpectTimeout(prompt, 10*time.Second))
		assert.FatalError(t, cmd.SendLine(k.password))
		k.testJwtSignVerify(t)
	})
}

func (k KeypairCmd) testNoPass(t *testing.T) {
	k.command.test(t, k.name, "", "")
	k.testJwtSignVerify(t)
}

func (k KeypairCmd) fail(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected, "")
}

func (k KeypairCmd) failNoPass(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected, "")
}

func NewKeypairCmd(name string) KeypairCmd {
	pubfile := fmt.Sprintf("%s/%s.pub", TempDirectory, name)
	prvfile := fmt.Sprintf("%s/%s.pem", TempDirectory, name)
	command := NewCLICommand().setCommand(fmt.Sprintf("step crypto keypair %s %s", pubfile, prvfile))
	return KeypairCmd{name, command, pubfile, prvfile, "password"}
}

func TestCryptoKeypair(t *testing.T) {
	NewCLICommand().setCommand("step crypto keypair").fail(t, "no-args", "missing positional arguments 'PUB_FILE' 'PRIV_FILE'\n", "")
	NewCLICommand().setCommand("step crypto keypair foo").fail(t, "no-args", "missing positional argument 'PRIV_FILE'\n", "")
	NewKeypairCmd("default").test(t)
	t.Run("RSA", func(t *testing.T) {
		NewKeypairCmd("RSA-default").setFlag("type", "RSA").test(t)
		NewKeypairCmd("RSA-size-0-fail").setFlag("type", "RSA").setFlag("size", "0").fail(t, "minimum '--size' for RSA keys is 2048 bits without '--insecure' flag\n")
		NewKeypairCmd("RSA-size-16-fail").setFlag("type", "RSA").setFlag("size", "16").fail(t, "minimum '--size' for RSA keys is 2048 bits without '--insecure' flag\n")
		NewKeypairCmd("RSA-size-neg1-fail").setFlag("type", "RSA").setFlag("size", "-1").setFlag("insecure", "").fail(t, "--size must be >= 0\n")
		// Error when signing JWT: "error serializing JWT: crypto/rsa: message too long for RSA public key size"
		//NewKeypairCmd("RSA-size-16").setFlag("type", "RSA").setFlag("size", "16").setFlag("insecure", "").test(t)
		NewKeypairCmd("RSA-size-1024-fail").setFlag("type", "RSA").setFlag("size", "1024").fail(t, "minimum '--size' for RSA keys is 2048 bits without '--insecure' flag\n")
		NewKeypairCmd("RSA-size-1024").setFlag("type", "RSA").setFlag("size", "1024").setFlag("insecure", "").test(t)
		NewKeypairCmd("RSA-size-3072").setFlag("type", "RSA").setFlag("size", "3072").test(t)
		NewKeypairCmd("RSA-size-4096").setFlag("type", "RSA").setFlag("size", "4096").test(t)
		NewKeypairCmd("RSA-curve").setFlag("type", "RSA").setFlag("crv", "P-256").fail(t, "key type 'RSA' is not compatible with flag '--crv'\n")
	})
	t.Run("EC", func(t *testing.T) {
		NewKeypairCmd("EC-default").setFlag("type", "EC").test(t)
		NewKeypairCmd("P-256").setFlag("type", "EC").setFlag("crv", "P-256").test(t)
		NewKeypairCmd("P-384").setFlag("type", "EC").setFlag("curve", "P-384").test(t)
		NewKeypairCmd("P-521").setFlag("type", "EC").setFlag("crv", "P-521").test(t)
		NewKeypairCmd("bad-crv").setFlag("type", "EC").setFlag("curve", "P-512").fail(t, "invalid value for argument crv (crv: 'P-512')\n")
		NewKeypairCmd("EC-size").setFlag("type", "EC").setFlag("size", "2048").fail(t, "key type 'EC' is not compatible with flag '--size'\n")
	})
	NewKeypairCmd("bad-type").setFlag("type", "foo").fail(t, "unrecognized key type: foo\n")
	NewKeypairCmd("no-pass-fail").setFlag("no-password", "").failNoPass(t, "flag '--no-password' requires the '--insecure' flag\n")
	NewKeypairCmd("no-pass").setPassword("").setFlag("no-password", "").setFlag("insecure", "").testNoPass(t)
}
