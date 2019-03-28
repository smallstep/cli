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
	if k.command.flags["kty"] == "RSA" {
		test = test.setFlag("alg", "RS256")
	}
	test.test(t, fmt.Sprintf("%s-jwt-sign-verify", k.name))
}

func (k KeypairCmd) test(t *testing.T) {
	t.Run(k.name, func(t *testing.T) {
		cmd, err := gexpect.Spawn(k.command.cmd())
		assert.FatalError(t, err)
		prompt := fmt.Sprintf("Please enter the password to encrypt the private key: ")
		assert.FatalError(t, cmd.ExpectTimeout(prompt, 15*time.Second))
		assert.FatalError(t, cmd.SendLine(k.password))
		k.testJwtSignVerify(t)
	})
}

func (k KeypairCmd) testNoPass(t *testing.T) {
	k.command.test(t, k.name, "Your public key has been saved in testdata-tmp/no-pass.pub.\nYour private key has been saved in testdata-tmp/no-pass.pem.\n")
	k.testJwtSignVerify(t)
}

func (k KeypairCmd) fail(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected)
}

func (k KeypairCmd) failNoPass(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected)
}

func NewKeypairCmd(name string) KeypairCmd {
	pubfile := fmt.Sprintf("%s/%s.pub", TempDirectory, name)
	prvfile := fmt.Sprintf("%s/%s.pem", TempDirectory, name)
	command := NewCLICommand().setCommand(fmt.Sprintf("step crypto keypair %s %s", pubfile, prvfile))
	return KeypairCmd{name, command, pubfile, prvfile, "password"}
}

func TestCryptoKeypair(t *testing.T) {
	NewCLICommand().setCommand("step crypto keypair").fail(t, "no-args", "not enough positional arguments were provided in 'step crypto keypair <pub_file> <priv_file>'\n", "")
	NewCLICommand().setCommand("step crypto keypair foo").fail(t, "no-args", "not enough positional arguments were provided in 'step crypto keypair <pub_file> <priv_file>'\n", "")
	NewKeypairCmd("default").test(t)
	t.Run("RSA", func(t *testing.T) {
		NewKeypairCmd("RSA-default").setFlag("kty", "RSA").test(t)
		NewKeypairCmd("RSA-size-0-fail").setFlag("kty", "RSA").setFlag("size", "0").fail(t, "flag '--size' requires at least 2048 unless '--insecure' flag is provided\n")
		NewKeypairCmd("RSA-size-16-fail").setFlag("kty", "RSA").setFlag("size", "16").fail(t, "flag '--size' requires at least 2048 unless '--insecure' flag is provided\n")
		NewKeypairCmd("RSA-size-neg1-fail").setFlag("kty", "RSA").setFlag("size", "-1").setFlag("insecure", "").fail(t, "flag '--size' must be greater or equal than 0\n")
		// Error when signing JWT: "error serializing JWT: crypto/rsa: message too long for RSA public key size"
		//NewKeypairCmd("RSA-size-16").setFlag("kty", "RSA").setFlag("size", "16").setFlag("insecure", "").test(t)
		NewKeypairCmd("RSA-size-1024-fail").setFlag("kty", "RSA").setFlag("size", "1024").fail(t, "flag '--size' requires at least 2048 unless '--insecure' flag is provided\n")
		NewKeypairCmd("RSA-size-1024").setFlag("kty", "RSA").setFlag("size", "1024").setFlag("insecure", "").test(t)
		NewKeypairCmd("RSA-size-3072").setFlag("kty", "RSA").setFlag("size", "3072").test(t)
		NewKeypairCmd("RSA-size-4096").setFlag("kty", "RSA").setFlag("size", "4096").test(t)
		NewKeypairCmd("RSA-curve").setFlag("kty", "RSA").setFlag("size", "2048").setFlag("crv", "P-256").fail(t, "flag '--curve' is incompatible with flag '--kty RSA'\n")
	})
	t.Run("EC", func(t *testing.T) {
		NewKeypairCmd("EC-default").setFlag("kty", "EC").test(t)
		NewKeypairCmd("P-256").setFlag("kty", "EC").setFlag("crv", "P-256").test(t)
		NewKeypairCmd("P-384").setFlag("kty", "EC").setFlag("curve", "P-384").test(t)
		NewKeypairCmd("P-521").setFlag("kty", "EC").setFlag("crv", "P-521").test(t)
		NewKeypairCmd("bad-crv").setFlag("kty", "EC").setFlag("curve", "P-512").fail(t, "flag '--kty EC' is incompatible with flag '--curve P-512'\n\n  Option(s): --curve P-256, P-384, P-521\n")
		NewKeypairCmd("EC-size").setFlag("kty", "EC").setFlag("size", "2048").fail(t, "flag '--size' is incompatible with flag '--kty EC'\n")
	})
	NewKeypairCmd("bad-type").setFlag("kty", "foo").fail(t, "invalid value 'foo' for flag '--kty'; options are RSA, EC, OKP\n")
	NewKeypairCmd("no-pass-fail").setFlag("no-password", "").failNoPass(t, "flag '--insecure' requires the '--no-password' flag\n")
	NewKeypairCmd("no-pass").setPassword("").setFlag("no-password", "").setFlag("insecure", "").testNoPass(t)
}
