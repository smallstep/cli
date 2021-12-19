//go:build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/utils"
)

func TestCertificateFormat(t *testing.T) {
	setup()
	t.Run("validate cert and key extraction from p12", func(t *testing.T) {
        _, err := NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format %s", temp("foo.p12"))).
			setFlag("crt", temp("foo_out0.crt")).
			setFlag("key", temp("foo_out0.key")).
			setFlag("ca", temp("intermediate-ca_out0.crt")).
			setFlag("format", "pem").
			setFlag("no-password", "").
			run()
		assert.Nil(t, err)

		foo_crt, _ := pemutil.ReadCertificate(temp("foo.crt"))
		foo_crt_out, _ := pemutil.ReadCertificate(temp("foo_out0.crt"))
		assert.Equals(t, foo_crt, foo_crt_out)

		foo_key, _ := utils.ReadFile(temp("foo.key"))
		foo_out_key, _ := utils.ReadFile(temp("foo_out0.key"))
		assert.Equals(t, foo_key, foo_out_key)

		foo_ca, _ := pemutil.ReadCertificate(temp("intermediate-ca_out0.crt"))
		foo_ca_out, _ := pemutil.ReadCertificate(temp("intermediate-ca_out0.crt"))
		assert.Equals(t, foo_ca, foo_ca_out)
	})

	t.Run("validate cert and key packaging to p12", func(t *testing.T) {
		_, err := NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format %s", temp("foo.crt"))).
			setFlag("crt", temp("foo_format.p12")).
			setFlag("key", temp("foo.key")).
			setFlag("ca", temp("intermediate-ca.crt")).
			setFlag("format", "p12").
			setFlag("no-password", "").
			setFlag("insecure", "").
			run()
		assert.Nil(t, err)

		_, err = NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format %s", temp("foo_format.p12"))).
			setFlag("crt", temp("foo_out1.crt")).
			setFlag("key", temp("foo_out1.key")).
			setFlag("ca", temp("intermediate-ca_out1.crt")).
			setFlag("format", "pem").
			setFlag("no-password", "").
			run()

		assert.Nil(t, err)

		foo_crt, _ := pemutil.ReadCertificate(temp("foo.crt"))
		foo_crt_out, _ := pemutil.ReadCertificate(temp("foo_out1.crt"))
		assert.Equals(t, foo_crt, foo_crt_out)

		foo_key, _ := utils.ReadFile(temp("foo.key"))
		foo_out_key, _ := utils.ReadFile(temp("foo_out1.key"))
		assert.Equals(t, foo_key, foo_out_key)

		foo_ca, _ := pemutil.ReadCertificate(temp("intermediate-ca.crt"))
		foo_ca_out, _ := pemutil.ReadCertificate(temp("intermediate-ca_out1.crt"))
		assert.Equals(t, foo_ca, foo_ca_out)
	})

	t.Run("validate stdout output", func(t *testing.T) {
        output, err := NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format %s", temp("foo.p12"))).
			setFlag("no-password", "").
			setFlag("key", temp("temp.key")).
			setFlag("ca", temp("temp.crt")).
			setFlag("format", "pem").
			run()
		assert.Nil(t, err)

		foo_crt, _ := pemutil.ReadCertificate(temp("foo.crt"))
		foo_crt_out, _ := pemutil.Parse([]byte(output.stdout))
		assert.Equals(t, foo_crt, foo_crt_out)
	})

	t.Run("compare der format", func(t *testing.T) {
		_, err := NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format")).
			setArguments(temp("foo.crt")).
			setFlag("out", temp("foo.der")).
			run()
		assert.Nil(t, err)


		_, err = NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format %s", temp("foo.p12"))).
			setFlag("no-password", "").
			setFlag("format", "der").
			setFlag("crt", temp("foo_cmp.der")).
			run()

		assert.Nil(t, err)

		foo_crt, _ := pemutil.ReadCertificate(temp("foo.der"))
		foo_crt_out, _ := pemutil.ReadCertificate(temp("foo_cmp.der"))
		assert.Equals(t, foo_crt, foo_crt_out)
	})

	t.Run("validate interconversion between PEM and DER", func(t *testing.T) {
		_, err := NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format")).
			setArguments(temp("foo.crt")).
			setFlag("out", temp("foo_inter.der")).
			run()
		assert.Nil(t, err)

		_, err = NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format")).
			setArguments(temp("foo_inter.der")).
			setFlag("out", temp("foo_inter.crt")).
			run()
		assert.Nil(t, err)

		assert.Nil(t, err)

		foo_crt, _ := pemutil.ReadCertificate(temp("foo.crt"))
		foo_crt_out, _ := pemutil.ReadCertificate(temp("foo_inter.crt"))
		assert.Equals(t, foo_crt, foo_crt_out)
	})

	t.Run("assert incompatible flag", func(t *testing.T) {
		output, _ := NewCLICommand().
			setCommand(fmt.Sprintf("../bin/step certificate format %s", temp("foo.p12"))).
			setFlag("out", temp("some")).
			setFlag("key", temp("some")).
			run()
		assert.Equals(t, "flag '--out' is incompatible with '--key'\n", output.stderr)
	})

}

func setup() {
	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate create root-ca %s %s", temp("root-ca.crt"), temp("root-ca.key"))).
		setFlag("profile", "root-ca").
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()

	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate create intermediate-ca %s %s", temp("intermediate-ca.crt"), temp("intermediate-ca.key"))).
		setFlag("profile", "intermediate-ca").
		setFlag("ca", temp("root-ca.crt")).
		setFlag("ca-key", temp("root-ca.key")).
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()

	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate create foo %s %s", temp("foo.crt"), temp("foo.key"))).
		setFlag("profile", "leaf").
		setFlag("ca", temp("intermediate-ca.crt")).
		setFlag("ca-key", temp("intermediate-ca.key")).
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()

	NewCLICommand().
		setCommand(fmt.Sprintf("../bin/step certificate p12 %s %s %s", temp("foo.p12"), temp("foo.crt"), temp("foo.key"))).
		setFlag("ca", temp("intermediate-ca.crt")).
		setFlag("no-password", "").
		setFlag("insecure", "").
		run()
}

func temp(filename string) string {
	return fmt.Sprintf("%s/%s", TempDirectory, filename)
}
