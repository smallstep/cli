package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/utils"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:      "inspect",
		Action:    command.ActionFunc(inspectAction),
		Usage:     `print key details in human readable format`,
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
'''

## NOTES

This command shows the raw parameters of the keys, it does not include headers
that the marshaled version of the keys might have. For example, a marshaled
version an EC public key will have 0x04 in the first byte to indicate the
uncompressed form specified in section 4.3.6 of ANSI X9.62.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "password-file",
				Usage: "The path to the <file> containing passphrase to decrypt private key.",
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

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	var key interface{}
	switch {
	case bytes.HasPrefix(b, []byte("-----BEGIN ")):
		opts := []pemutil.Options{
			pemutil.WithFilename(name),
			pemutil.WithFirstBlock(),
		}
		if passFile := ctx.String("password-file"); passFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(passFile))
		}
		if key, err = pemutil.ParseKey(b, opts...); err != nil {
			return err
		}
	case isSSHPublicKey(b):
		if key, err = pemutil.ParseSSH(b); err != nil {
			return err
		}
	case isJWK(b):
		if key, err = parseJWK(ctx, b); err != nil {
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
		bigIntPaddedPrinter("Modulus", k.N, k.Size())
		fmt.Printf("Exponent: %d (0x%x)\n", k.E, k.E)
	case *rsa.PrivateKey:
		fmt.Printf("RSA Private-Key: (%d bit)\n", k.Size()*8)
		bigIntPaddedPrinter("Modulus", k.N, k.Size())
		fmt.Printf("Public Exponent: %d (0x%x)\n", k.E, k.E)
		bigIntPaddedPrinter("Private Exponent", k.D, k.Size())
		for i := range k.Primes {
			bigIntPrinter(fmt.Sprintf("Prime #%d", i+1), k.Primes[i])
		}
		bigIntPrinter("Exponent #1", k.Precomputed.Dp)
		bigIntPrinter("Exponent #2", k.Precomputed.Dq)
		bigIntPrinter("Coefficient", k.Precomputed.Qinv)
	case *ecdsa.PublicKey:
		byteLen := (k.Params().BitSize + 7) >> 3
		fmt.Printf("EC Public-Key: (%d bit)\n", k.Params().BitSize)
		bigIntPaddedPrinter("X", k.X, byteLen)
		bigIntPaddedPrinter("Y", k.Y, byteLen)
		fmt.Printf("Curve: %s\n", k.Params().Name)
	case *ecdsa.PrivateKey:
		byteLen := (k.Params().BitSize + 7) >> 3
		fmt.Printf("EC PrivateKey-Key: (%d bit)\n", k.Params().BitSize)
		bigIntPaddedPrinter("X", k.X, byteLen)
		bigIntPaddedPrinter("Y", k.Y, byteLen)
		bigIntPaddedPrinter("D", k.D, byteLen)
		fmt.Printf("Curve: %s\n", k.Params().Name)
	case ed25519.PublicKey:
		fmt.Printf("Ed25519 Public-Key: (%d bit)\n", 8*len(k))
		bytesPrinter("Public", k)
	case ed25519.PrivateKey:
		fmt.Printf("Ed25519 Private-Key: (%d bit)\n", 8*len(k))
		bytesPrinter("Public", k[32:])
		bytesPrinter("Private", k[:32])
	default:
		return errors.Errorf("unsupported key type '%T'", k)
	}

	return nil
}

func bigIntPrinter(name string, val *big.Int) {
	bytesPrinter(name, val.Bytes())
}

func bigIntPaddedPrinter(name string, val *big.Int, size int) {
	bytesPrinter(name, paddedBytes(val.Bytes(), size))
}

func bytesPrinter(name string, bs []byte) {
	fmt.Print(name + ":")
	for i, b := range bs {
		if (i % 16) == 0 {
			fmt.Print("\n    ")
		}
		fmt.Printf("%02x", b)
		if i != len(bs)-1 {
			fmt.Print(":")
		}
	}
	fmt.Println()
}

func paddedBytes(b []byte, size int) []byte {
	ret := make([]byte, size)
	copy(ret[len(ret)-len(b):], b)
	return ret
}
