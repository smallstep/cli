// +build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/smallstep/assert"
)

const (
	totpSecretFile = "testdata/totp.secret"
	totpSecret     = "UPCTJYT7MUR4RWOUJ3TGTUB43IYCBJ76"
	totpUrlFile    = "testdata/totp.url"
	totpUrl        = "otpauth://totp/example.com:foo@example.com?algorithm=SHA1&digits=6&issuer=example.com&period=30&secret=EW32D2CFTAIRTEAWTRQZZXAITVA4U6K4"
)

func mkotp(subcommand string, flags map[string]string) CLICommand {
	return CLICommand{fmt.Sprintf("step crypto otp %s", subcommand), "", flags, nil}
}

func TestCryptoOtp(t *testing.T) {
	c := mkotp("generate", map[string]string{"issuer": "example.com", "account": "foo@example.com"})
	t.Run("generate", func(t *testing.T) {
		out, err := c.run()
		assert.Nil(t, err)
		assert.Equals(t, len(strings.TrimSuffix(out.combined, "\n")), 32)
	})

	c = mkotp("generate", map[string]string{"issuer": "example.com", "account": "foo@example.com", "url": ""})
	t.Run("generate-url", func(t *testing.T) {
		out, err := c.run()
		assert.Nil(t, err)
		assert.True(t, strings.HasPrefix(out.combined, "otpauth://"))
		key, err := otp.NewKeyFromURL(out.combined)
		assert.Nil(t, err)
		assert.Equals(t, key.Type(), "totp")
		assert.Equals(t, key.Issuer(), "example.com")
		assert.Equals(t, key.AccountName(), "foo@example.com")
		assert.True(t, len(key.Secret()) == 32)
	})

	c = mkotp("verify", map[string]string{"secret": totpSecretFile})
	t.Run("verify", func(t *testing.T) {
		code, err := totp.GenerateCode(totpSecret, time.Now())
		assert.Nil(t, err)
		out, err := c.setStdin(code).run()
		assert.Nil(t, err)
		assert.Equals(t, "Enter Passcode: ok\n", out.combined)
		out, err = c.setStdin("foo").run()
		assert.NotNil(t, err)
		assert.Equals(t, "Enter Passcode: fail\n", out.combined)
	})

	c = mkotp("verify", map[string]string{"secret": totpUrlFile})
	t.Run("verify-url", func(t *testing.T) {
		key, err := otp.NewKeyFromURL(totpUrl)
		assert.FatalError(t, err)
		code, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)
		out, err := c.setStdin(code).run()
		assert.Nil(t, err)
		assert.Equals(t, "Enter Passcode: ok\n", out.combined)
		out, err = c.setStdin("foo").run()
		assert.NotNil(t, err)
		assert.Equals(t, "Enter Passcode: fail\n", out.combined)
	})
}
