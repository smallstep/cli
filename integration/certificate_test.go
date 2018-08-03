// +build integration

package integration

import (
	"fmt"
	"testing"
)

var testdata = "testdata"

type CertificateCreateCmd struct {
	name      string
	command   CLICommand
	csr       string
	issuerCrt string
	issuerKey string
	pass      string
}

func (k CertificateCreateCmd) setPass(pass string) CertificateCreateCmd {
	return CertificateCreateCmd{k.name, k.command, k.csr, k.issuerCrt, k.issuerKey, pass}
}

/*
func (k CertificateCreateCmd) test(t *testing.T) {
	t.Run(k.name, func(t *testing.T) {
		cmd, err := gexpect.Spawn(k.command.cmd())
		assert.FatalError(t, err)
		prompt := fmt.Sprintf("Password with which to encrypt private key file `%s`: ", k.issuerKey)
		assert.FatalError(t, cmd.ExpectTimeout(prompt, 10*time.Second))
		assert.FatalError(t, cmd.SendLine(k.pass))
		k.testJwtSignVerify(t)
	})
}

func (k CertificateCreateCmd) testNoPass(t *testing.T) {
	k.command.test(t, k.name, "", "")
	k.testJwtSignVerify(t)
}
*/

func (k CertificateCreateCmd) fail(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected, "")
}

func (k CertificateCreateCmd) failNoPass(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected, "")
}

func NewCertificateCreateCmd(name, csr, crt, key string) CertificateCreateCmd {
	csrFile := fmt.Sprintf("%s/%s", testdata, csr)
	crtFile := fmt.Sprintf("%s/%s", testdata, crt)
	keyFile := fmt.Sprintf("%s/%s", testdata, key)
	command := NewCLICommand().setCommand(fmt.Sprintf("step certificate sign %s %s %s",
		csrFile, crtFile, keyFile))
	return CertificateCreateCmd{name, command, csrFile, crtFile, keyFile, "password"}
}

func TestCertificate(t *testing.T) {
	NewCertificateCreateCmd("bad-sig", "certificate-create-bad-sig.csr", "intermediate_ca.crt", "intermediate_ca_key").failNoPass(t, "Certificate Request has invalid signature: crypto/rsa: verification error\n")
	//NewKeypairCmd("success", "foo.csr", "intermediate_ca.crt", "intermediate_ca_key").setPass("pass").test(t)
}
