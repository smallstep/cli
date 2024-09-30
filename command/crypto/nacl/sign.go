package nacl

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/sign"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:      "sign",
		Usage:     "sign small messages using public-key cryptography",
		UsageText: "step crypto nacl sign <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto nacl sign** command group uses public-key cryptography to sign and
verify messages. The implementation is based on NaCl's crypto_sign function.

NaCl crypto_sign is crypto_sign_edwards25519sha512batch, a particular
combination of Curve25519 in Edwards form and SHA-512 into a signature scheme
suitable for high-speed batch verification. This function is conjectured to meet
the standard notion of unforgeability under chosen-message attacks.

These commands are interoperable with NaCl: https://nacl.cr.yp.to/sign.html

## EXAMPLES

Create a keypair for verifying and signing messages:
'''
$ step crypto nacl sign keypair nacl.sign.pub nacl.sign.priv
'''

Sign a message using the private key:
'''
$ step crypto nacl sign sign nacl.sign.priv
Please enter text to sign: ********
rNrOfqsv4svlRnVPSVYe2REXodL78yEMHtNkzAGNp4MgHuVGoyayp0zx4D5rjTzYVVrD2HRP306ZILT62ohvCG1lc3NhZ2U

$ cat message.txt | step crypto nacl sign sign ~/step/keys/nacl.recipient.sign.priv
rNrOfqsv4svlRnVPSVYe2REXodL78yEMHtNkzAGNp4MgHuVGoyayp0zx4D5rjTzYVVrD2HRP306ZILT62ohvCG1lc3NhZ2U
'''

Verify the signed message using the public key:
'''
$ echo rNrOfqsv4svlRnVPSVYe2REXodL78yEMHtNkzAGNp4MgHuVGoyayp0zx4D5rjTzYVVrD2HRP306ZILT62ohvCG1lc3NhZ2U \
     | step crypto nacl sign open nacl.sign.pub
message
'''`,
		Subcommands: cli.Commands{
			signKeypairCommand(),
			signOpenCommand(),
			signSignCommand(),
		},
	}
}

func signKeypairCommand() cli.Command {
	return cli.Command{
		Name:      "keypair",
		Action:    command.ActionFunc(signKeypairAction),
		Usage:     "generate a pair for use with sign and open",
		UsageText: "**step crypto nacl sign keypair** <pub-file> <priv-file>",
		Description: `**step crypto nacl sign keypair** generates a secret key and a corresponding
public key valid for verifying and signing messages.

This command uses an implementation of NaCl's crypto_sign_keypair function.

For examples, see **step help crypto nacl sign**.`,
		Flags: []cli.Flag{flags.Force},
	}
}

func signOpenCommand() cli.Command {
	return cli.Command{
		Name:      "open",
		Action:    cli.ActionFunc(signOpenAction),
		Usage:     "verify a signed message produced by sign",
		UsageText: "**step crypto nacl sign open** <pub-file>",
		Description: `**step crypto nacl sign open** verifies the signature of a message using the
signer's public key.

This command uses an implementation of NaCl's crypto_sign_open function.

For examples, see **step help crypto nacl sign**.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Indicates that input is not base64 encoded",
			},
		},
	}
}

func signSignCommand() cli.Command {
	return cli.Command{
		Name:      "sign",
		Action:    cli.ActionFunc(signSignAction),
		Usage:     "sign a message using Ed25519",
		UsageText: "**step crypto nacl sign sign** <priv-file>",
		Description: `**step crypto nacl sign sign** signs a message m using the signer's private
key.

This command uses an implementation of NaCl's crypto_sign function.

For examples, see **step help crypto nacl sign**.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Do not base64 encode output",
			},
		},
	}
}

func signKeypairAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	pubFile, privFile := args[0], args[1]
	if pubFile == privFile {
		return errs.EqualArguments(ctx, "<pub-file>", "<priv-file>")
	}

	pub, priv, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Wrap(err, "error generating key")
	}

	if err := utils.WriteFile(pubFile, pub[:], 0600); err != nil {
		return errs.FileError(err, pubFile)
	}

	if err := utils.WriteFile(privFile, priv[:], 0600); err != nil {
		return errs.FileError(err, privFile)
	}

	ui.Printf("Your public key has been saved in %s.\n", pubFile)
	ui.Printf("Your private key has been saved in %s.\n", privFile)
	return nil
}

func signOpenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	pubFile := ctx.Args().Get(0)
	pub, err := os.ReadFile(pubFile)
	if err != nil {
		return errs.FileError(err, pubFile)
	} else if len(pub) != 32 {
		return errors.New("invalid public key: key size is not 32 bytes")
	}

	input, err := utils.ReadInput("Write signed message to open")
	if err != nil {
		return errors.Wrap(err, "error reading input")
	}

	var rawInput []byte
	if ctx.Bool("raw") {
		rawInput = input
	} else {
		// DecodeLen returns the maximum length,
		// Decode will return the actual length.
		rawInput = make([]byte, b64Encoder.DecodedLen(len(input)))
		n, err := b64Encoder.Decode(rawInput, input)
		if err != nil {
			return errors.Wrap(err, "error decoding base64 input")
		}
		rawInput = rawInput[:n]
	}

	var pb [32]byte
	copy(pb[:], pub)

	raw, ok := sign.Open(nil, rawInput, &pb)
	if !ok {
		return errors.New("error authenticating input")
	}

	os.Stdout.Write(raw)
	return nil
}

func signSignAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	privFile := ctx.Args().Get(0)
	priv, err := os.ReadFile(privFile)
	if err != nil {
		return errs.FileError(err, privFile)
	} else if len(priv) != 64 {
		return errors.New("invalid private key: key size is not 64 bytes")
	}

	input, err := utils.ReadInput("Please enter text to sign")
	if err != nil {
		return errors.Wrap(err, "error reading input")
	}

	var pv [64]byte
	copy(pv[:], priv)

	raw := sign.Sign(nil, input, &pv)
	if ctx.Bool("raw") {
		os.Stdout.Write(raw)
	} else {
		fmt.Println(b64Encoder.EncodeToString(raw))
	}

	return nil
}
