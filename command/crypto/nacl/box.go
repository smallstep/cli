package nacl

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/box"
)

func boxCommand() cli.Command {
	return cli.Command{
		Name:      "box",
		Usage:     "authenticate and encrypt small messages using public-key cryptography",
		UsageText: "step crypto nacl box <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			boxKeypairCommand(),
			boxOpenCommand(),
			boxSealCommand(),
		},
	}
}

func boxKeypairCommand() cli.Command {
	return cli.Command{
		Name:      "keypair",
		Action:    cli.ActionFunc(boxKeypairAction),
		Usage:     "generate a key for use with seal and open",
		UsageText: "**step crypto nacl box keypair** <pub-file> <priv-file>",
		Description: `Generates a new public/private keypair suitable for use with seal and open.
The private key is encrypted using a password in a nacl secretbox.

## POSITIONAL ARGUMENTS

<pub-file>
:  The path to write the public key.

<priv-file>
:  The path to write the encrypted private key.`,
	}
}

func boxOpenCommand() cli.Command {
	return cli.Command{
		Name:   "open",
		Action: cli.ActionFunc(boxOpenAction),
		Usage:  "authenticate and decrypt a box produced by seal",
		UsageText: `**step crypto nacl box open** <nonce> <sender-pub-key> <priv-key>
		[--raw]`,
		Description: `Authenticate and decrypt a box produced by seal using the specified KEY. If
PRIV_KEY is encrypted you will be prompted for the password. The sealed box is
read from STDIN and the decrypted plaintext is written to STDOUT.

## POSITIONAL ARGUMENTS

<nonce>
:  The nonce provided when the box was sealed.

<sender-pub-key>
:  The path to the public key of the peer that produced the sealed box.

<priv-key>
:  The path to the private key used to open the box.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Indicates that input is not base64 encoded",
			},
		},
	}
}

func boxSealCommand() cli.Command {
	return cli.Command{
		Name:   "seal",
		Action: cli.ActionFunc(boxSealAction),
		Usage:  "produce an authenticated and encrypted ciphertext",
		UsageText: `**step crypto nacl box seal** <nonce> <recipient-pub-key> <priv-key>
		[--raw]`,
		Description: `Reads plaintext from STDIN and writes an encrypted and authenticated
ciphertext to STDOUT. The "box" can be open by the a recipient who has access
to the private key corresponding to <recipient-pub-key>.

## POSITIONAL ARGUMENTS

<nonce>
:  Must be unique for each distinct message for a given pair of keys.

<recipient-pub-key>
:  The path to the public key of the intended recipient of the sealed box.

<priv-key>
:  The path to the private key used for authentication.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Do not base64 encode output",
			},
		},
	}
}

func boxKeypairAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	pubFile, privFile := args[0], args[1]
	if pubFile == privFile {
		return errs.EqualArguments(ctx, "<pub-file>", "<priv-file>")
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Wrap(err, "error generating key")
	}

	if err := utils.WriteFile(pubFile, pub[:], 0600); err != nil {
		return errs.FileError(err, pubFile)
	}

	if err := utils.WriteFile(privFile, priv[:], 0600); err != nil {
		return errs.FileError(err, privFile)
	}

	return nil
}

func boxOpenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, pubFile, privFile := []byte(args[0]), args[1], args[2]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	pub, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return errs.FileError(err, pubFile)
	} else if len(pub) != 32 {
		return errors.New("invalid public key: key size is not 32 bytes")
	}

	priv, err := ioutil.ReadFile(privFile)
	if err != nil {
		return errs.FileError(err, privFile)
	} else if len(priv) != 32 {
		return errors.New("invalid private key: key size is not 32 bytes")
	}

	input, err := utils.ReadAll(os.Stdin)
	if err != nil {
		return errs.Wrap(err, "error reading input")
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

	var n [24]byte
	var pb, pv [32]byte
	copy(n[:], nonce)
	copy(pb[:], pub)
	copy(pv[:], priv)

	// Fixme: if we prepend the nonce in the seal we can use use rawInput[24:]
	// as the message and rawInput[:24] as the nonce instead of requiring one.
	raw, ok := box.Open(nil, rawInput, &n, &pb, &pv)
	if !ok {
		return errors.New("error authenticating or decrypting input")
	}

	os.Stdout.Write(raw)
	return nil
}

func boxSealAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, pubFile, privFile := []byte(args[0]), args[1], args[2]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	pub, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return errs.FileError(err, pubFile)
	} else if len(pub) != 32 {
		return errors.New("invalid public key: key size is not 32 bytes")
	}

	priv, err := ioutil.ReadFile(privFile)
	if err != nil {
		return errs.FileError(err, privFile)
	} else if len(priv) != 32 {
		return errors.New("invalid private key: key size is not 32 bytes")
	}

	input, err := utils.ReadInput("Write text to seal: ")
	if err != nil {
		return errors.Wrap(err, "error reading input")
	}

	var n [24]byte
	var pb, pv [32]byte
	copy(n[:], nonce)
	copy(pb[:], pub)
	copy(pv[:], priv)

	// Fixme: we can prepend nonce[:] so it's not necessary in the open.
	raw := box.Seal(nil, input, &n, &pb, &pv)
	if ctx.Bool("raw") {
		os.Stdout.Write(raw)
	} else {
		fmt.Println(b64Encoder.EncodeToString(raw))
	}

	return nil
}
