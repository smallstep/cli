package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:      "inspect",
		Action:    command.ActionFunc(inspectAction),
		Usage:     `print key deatails in human readable format`,
		UsageText: `**step crypto key inspect** <key-file>`,
		Description: `**step crypto key inspect** prints details of a public or a private key in a
human readable format the public key corresponding to the given <key-file>.

## POSITIONAL ARGUMENTS

<key-file>
:  Path to a public or private key.

## EXAMPLES

Print details of the given key:
'''
$ step crypto key inspect priv.pem
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

	var key interface{}
	switch {
	case bytes.HasPrefix(b, []byte("-----BEGIN ")):
		if key, err = pemutil.ParseKey(b); err != nil {
			return err
		}
	case isSSHPublicKey(b):
		if key, err = pemutil.ParseSSH(b); err != nil {
			return err
		}
	default: // assume DER format
		if key, err = pemutil.ParseDER(b); err != nil {
			return err
		}
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		fmt.Printf("RSA Public-Key: (%d bit)\n", k.Size()*8)
		bigIntPrinter("Modulus", k.N)
		fmt.Printf("Exponent: %d (0x%x)\n", k.E, k.E)
	case *rsa.PrivateKey:
		fmt.Printf("RSA Private-Key: (%d bit)\n", k.Size()*8)
		bigIntPrinter("Modulus", k.N)
		fmt.Printf("Public Exponent: %d (0x%x)\n", k.E, k.E)
		bigIntPrinter("Private Exponent", k.D)
		for i := range k.Primes {
			bigIntPrinter(fmt.Sprintf("Prime #%d", i+1), k.Primes[i])
		}
		bigIntPrinter("Exponent #1", k.Precomputed.Dp)
		bigIntPrinter("Exponent #2", k.Precomputed.Dq)
		bigIntPrinter("Coefficient", k.Precomputed.Qinv)
	case *ecdsa.PublicKey:
		fmt.Printf("ECDSA Public-Key: (%d bit)\n", k.Params().BitSize)
		bigIntPrinter("X", k.X)
		bigIntPrinter("Y", k.Y)
		fmt.Printf("Curve: %s\n", k.Params().Name)
	case *ecdsa.PrivateKey:
		fmt.Printf("ECDSA PrivateKey-Key: (%d bit)\n", k.Params().BitSize)
		bigIntPrinter("X", k.X)
		bigIntPrinter("Y", k.Y)
		bigIntPrinter("D", k.D)
		fmt.Printf("Curve: %s\n", k.Params().Name)
	case ed25519.PublicKey:
		fmt.Printf("Ed25519 Public-Key: (%d bit)\n", 8*len(k))
		fmt.Print("Public:")
		bytesPrinter(k)
	case ed25519.PrivateKey:
		fmt.Printf("Ed25519 Private-Key: (%d bit)\n", 8*len(k))
		fmt.Print("Public:")
		bytesPrinter(k[32:])
		fmt.Print("Private:")
		bytesPrinter(k[:32])
	default:
		return errors.Errorf("unsupported key type '%T'", k)
	}

	return nil
}

func bigIntPrinter(name string, val *big.Int) {
	fmt.Print(name + ":")
	bytesPrinter(val.Bytes())
}

func bytesPrinter(bytes []byte) {
	for i, b := range bytes {
		if (i % 16) == 0 {
			fmt.Print("\n    ")
		}
		fmt.Printf("%02x", b)
		if i != len(bytes)-1 {
			fmt.Print(":")
		}
	}
	fmt.Println()
}
