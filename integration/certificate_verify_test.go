// build integration

package integration

import (
	"fmt"
	"testing"
)

type CertificateVerifyCmd struct {
	name    string
	command CLICommand
	crt     string
	host    string
	roots   string
}

/*
func (k CertificateSignCmd) test(t *testing.T) {
	t.Run(k.name, func(t *testing.T) {
		cmd, err := gexpect.Spawn(k.command.cmd())
		assert.FatalError(t, err)
		prompt := fmt.Sprintf("Password with which to encrypt private key file `%s`: ", k.issuerKey)
		assert.FatalError(t, cmd.ExpectTimeout(prompt, 10*time.Second))
		assert.FatalError(t, cmd.SendLine(k.pass))
		k.testJwtSignVerify(t)
	})
}
*/

func (k CertificateVerifyCmd) fail(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected, "")
}

func NewCertificateVerifyCmd(name, crt string) CertificateVerifyCmd {
	testdata := "testdata"
	crtFile := fmt.Sprintf("%s/%s", testdata, crt)
	command := NewCLICommand().setCommand(fmt.Sprintf("step certificate verify %s",
		crtFile))
	return CertificateVerifyCmd{name: name, command: command, crt: crt}
}

func TestCertificateVerify(t *testing.T) {
	NewCertificateVerifyCmd("bad-pem", "bad-pem.crt").fail(t, "Certificate Request has invalid signature: crypto/rsa: verification error\n")
	//NewKeypairCmd("success", "foo.csr", "intermediate_ca.crt", "intermediate_ca_key").setPass("pass").test(t)
}
