package ssh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils"
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
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format",
				Value: "text",
				Usage: `The output format for printing the introspection details.

: <format> is a string and must be one of:

    **text**
    :  Print output in unstructured text suitable for a human to read.

    **json**
    :  Print output in JSON format.`,
			},
		},
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

	var (
		format = ctx.String("format")
	)

	if format != "text" && format != "json" {
		return errs.InvalidFlagValue(ctx, "format", format, "text, json")
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		// Attempt to parse the key without the type.
		b = bytes.TrimSpace(b)
		keyBytes := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
		n, err := base64.StdEncoding.Decode(keyBytes, b)
		if err != nil {
			return errors.Wrap(err, "error parsing ssh certificate")
		}
		if pub, err = ssh.ParsePublicKey(keyBytes[:n]); err != nil {
			return errors.Wrap(err, "error parsing ssh certificate")
		}
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.Errorf("error decoding ssh certificate: %T is not an *ssh.Certificate", pub)
	}
	inspect, err := sshutil.InspectCertificate(cert)
	if err != nil {
		return err
	}

	switch format {
	case "text":
		space := ""
		fmt.Println(name + ":")
		fmt.Printf("%8sType: %s %s certificate\n", space, inspect.KeyName, inspect.Type)
		fmt.Printf("%8sPublic key: %s-CERT %s\n", space, inspect.KeyAlgo, inspect.KeyFingerprint)
		fmt.Printf("%8sSigning CA: %s %s (using %s)\n", space, inspect.SigningKeyAlgo, inspect.SigningKeyFingerprint, inspect.Signature.Type)
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
		fmt.Printf("%8sSignature:", space)
		for i, b := range cert.Signature.Blob {
			if (i % 16) == 0 {
				fmt.Printf("\n%16s", space)
			}
			fmt.Printf("%02x", b)
			if i != len(cert.Signature.Blob)-1 {
				fmt.Print(":")
			}
		}
		fmt.Println()

	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err := enc.Encode(inspect)
		if err != nil {
			return errors.WithStack(err)
		}
	default:
		return errs.InvalidFlagValue(ctx, "format", format, "text, json")
	}

	return nil
}
