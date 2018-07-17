package nacl

import (
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command/crypto/internal/utils"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func secretboxCommand() cli.Command {
	return cli.Command{
		Name:        "secretbox",
		Usage:       "encrypts and authenticates small messages using secret-key cryptography",
		UsageText:   "step crypto nacl secretbox SUBCOMMAND [SUBCOMMAND_FLAGS]",
		Description: `TODO`,
		Subcommands: cli.Commands{
			secretboxOpenCommand(),
			secretboxSealCommand(),
		},
	}
}

func secretboxOpenCommand() cli.Command {
	return cli.Command{
		Name:        "open",
		Action:      cli.ActionFunc(secretboxOpenAction),
		Usage:       "authenticates and decrypts a box produced by seal",
		UsageText:   "step crypto nacl secretbox open NONCE KEY_FILE [--raw]",
		Description: `TODO`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Indicates that input is not base64 encoded",
			},
		},
	}
}

func secretboxOpenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, keyFile := []byte(args[0]), args[1]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != 32 {
		return errors.New("invalid key file: key size is not 32 bytes")
	}

	input, err := utils.ReadAll(os.Stdin)
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

	var n [24]byte
	var k [32]byte
	copy(n[:], nonce)
	copy(k[:], key)

	// Fixme: if we prepend the nonce in the seal we can use use rawInput[24:]
	// as the message and rawInput[:24] as the nonce instead of requiring one.
	raw, ok := secretbox.Open(nil, rawInput, &n, &k)
	if !ok {
		return errors.New("error authenticating or decrypting input")
	}

	os.Stdout.Write(raw)
	return nil
}

func secretboxSealCommand() cli.Command {
	return cli.Command{
		Name:        "seal",
		Action:      cli.ActionFunc(secretboxSealAction),
		Usage:       "produces an encrypted ciphertext",
		UsageText:   "step crypto nacl secretbox seal NONCE KEY_FILE [--raw]",
		Description: `TODO`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Do not base64 encode output",
			},
		},
	}
}

func secretboxSealAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, keyFile := []byte(args[0]), args[1]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != 32 {
		return errors.New("invalid key: key size is not 32 bytes")
	}

	input, err := utils.ReadInput("Write text to seal: ")
	if err != nil {
		return errors.Wrap(err, "error reading input")
	}

	var n [24]byte
	var k [32]byte
	copy(n[:], nonce)
	copy(k[:], key)

	// Fixme: we can prepend nonce[:] so it's not necessary in the open.
	raw := secretbox.Seal(nil, input, &n, &k)
	if ctx.Bool("raw") {
		os.Stdout.Write(raw)
	} else {
		fmt.Println(b64Encoder.EncodeToString(raw))
	}

	return nil
}
