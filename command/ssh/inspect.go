package ssh

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/sshutil"
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
	inspect, err := sshutil.InspectCertificate(cert)
	if err != nil {
		return err
	}

	space := ""
	fmt.Println(name + ":")
	fmt.Printf("%8sType: %s %s certificate\n", space, inspect.KeyName, inspect.Type)
	fmt.Printf("%8sPublic key: %s-CERT %s\n", space, inspect.KeyAlgo, inspect.KeyFingerprint)
	fmt.Printf("%8sSigning CA: %s %s\n", space, inspect.SigningKeyAlgo, inspect.SigningKeyFingerprint)
	fmt.Printf("%8sKey ID: \"%s\"\n", space, inspect.KeyID)
	fmt.Printf("%8sSerial: %d\n", space, inspect.Serial)
	fmt.Printf("%8sValid: %s\n", space, inspect.Validity())
	fmt.Printf("%8sPrincipals: ", space)
	if len(inspect.Principals) == 0 {
		fmt.Println("(none)")
	} else {
		fmt.Println()
		for _, p := range inspect.Principals {
			fmt.Printf("%16s%s\n", space, p)
		}
	}
	fmt.Printf("%8sCritical Options: ", space)
	if len(inspect.CriticalOptions) == 0 {
		fmt.Println("(none)")
	} else {
		fmt.Println()
		for k, v := range inspect.CriticalOptions {
			fmt.Printf("%16s%s %v\n", space, k, v)
		}
	}
	fmt.Printf("%8sExtensions: ", space)
	if len(inspect.Extensions) == 0 {
		fmt.Println("(none)")
	} else {
		fmt.Println()
		for k, v := range inspect.Extensions {
			fmt.Printf("%16s%s %v\n", space, k, v)
		}
	}

	return nil
}
