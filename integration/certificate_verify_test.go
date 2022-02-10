//go:build integration
// +build integration

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

func (k CertificateVerifyCmd) fail(t *testing.T, expected string) {
	k.command.fail(t, k.name, expected, "")
}

func NewCertificateVerifyCmd(name, crt string) CertificateVerifyCmd {
	testdata := "testdata"
	crtFile := fmt.Sprintf("./%s/%s", testdata, crt)
	command := NewCLICommand().setCommand(fmt.Sprintf("step certificate verify %s",
		crtFile))
	return CertificateVerifyCmd{name: name, command: command, crt: crt}
}

func TestCertificateVerify(t *testing.T) {
	NewCertificateVerifyCmd("bad-pem", "bad-pem.crt").fail(t, "./testdata/bad-pem.crt contains an invalid PEM block\n")
	//NewKeypairCmd("success", "foo.csr", "intermediate_ca.crt", "intermediate_ca_key").setPass("pass").test(t)
}
