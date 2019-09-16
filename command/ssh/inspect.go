package ssh

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/smallstep/cli/crypto/sshutil"
	"golang.org/x/crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:      "inspect",
		Action:    command.ActionFunc(inspectAction),
		Usage:     "print the contents of an ssh certificate",
		UsageText: `**step ssh inspect** <crt-file>`,
		Description: `**step ssh inspect** command prints ssh certificate details in human readable
format.

## POSITIONAL ARGUMENTS

<crt-file>
:  The path to an ssh certificate.

## EXAMPLES

Prints the contents of id_ecdsa-cert.pub:
'''
$ step ssh inspect id_ecdsa-cert.pub
'''`,
	}
}

func inspectAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var name string
	switch ctx.NArg() {
	case 0:
		name = "-"
	case 1:
		name = ctx.Args().First()
	default:
		return errs.TooManyArguments(ctx)
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return errors.Wrap(err, "error parsing ssh certificate")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.Errorf("error decoding ssh certificate: %T is not an *ssh.Certificate", pub)
	}
	keyType, keySum, err := sshPublicKey(cert.Key)
	if err != nil {
		return err
	}
	sigType, sigSum, err := sshPublicKey(cert.SignatureKey)
	if err != nil {
		return err
	}

	space := ""
	fmt.Println(name + ":")
	fmt.Printf("%8sType: %s %s certificate\n", space, cert.Type(), sshCertType(cert))
	fmt.Printf("%8sPublic key: %s-CERT %s\n", space, keyType, keySum)
	fmt.Printf("%8sSigning CA: %s %s\n", space, sigType, sigSum)
	fmt.Printf("%8sKey ID: \"%s\"\n", space, cert.KeyId)
	fmt.Printf("%8sSerial: %d\n", space, cert.Serial)
	fmt.Printf("%8sValid: %s\n", space, sshValidity(cert))
	fmt.Printf("%8sPrincipals: ", space)
	if len(cert.ValidPrincipals) == 0 {
		fmt.Println("(none)")
	} else {
		fmt.Println()
		for _, p := range cert.ValidPrincipals {
			fmt.Printf("%16s%s\n", space, p)
		}
	}
	fmt.Printf("%8sCritical Options: ", space)
	if len(cert.CriticalOptions) == 0 {
		fmt.Println("(none)")
	} else {
		fmt.Println()
		for k, v := range cert.CriticalOptions {
			fmt.Printf("%16s%s %v\n", space, k, v)
		}
	}
	fmt.Printf("%8sExtensions: ", space)
	if len(cert.Extensions) == 0 {
		fmt.Println("(none)")
	} else {
		fmt.Println()
		for k, v := range cert.Extensions {
			fmt.Printf("%16s%s %v\n", space, k, v)
		}
	}

	return nil
}

func sshCertType(cert *ssh.Certificate) string {
	switch cert.CertType {
	case ssh.HostCert:
		return "host"
	case ssh.UserCert:
		return "user"
	default:
		return "unknown"
	}
}

func sshPublicKey(key ssh.PublicKey) (string, string, error) {
	pub, err := sshutil.PublicKey(key)
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256(key.Marshal())
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	switch k := pub.(type) {
	case *dsa.PublicKey:
		return "DSA", fp, nil
	case *rsa.PublicKey:
		return "RSA", fp, nil
	case *ecdsa.PublicKey:
		return "ECDSA", fp, nil
	case ed25519.PublicKey:
		return "ED25519", fp, nil
	default:
		return "", "", errors.Errorf("unsupported public key %T", k)
	}
}

func sshValidity(cert *ssh.Certificate) string {
	const layout = "2006-01-02T15:04:05"
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return "forever"
	}
	from := time.Unix(int64(cert.ValidAfter), 0).Local()
	to := time.Unix(int64(cert.ValidBefore), 0).Local()
	return fmt.Sprintf("from %s to %s", from.Format(layout), to.Format(layout))
}
