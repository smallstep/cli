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
	"golang.org/x/crypto/nacl/sign"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:      "sign",
		Usage:     "signs small messages using public-key cryptography",
		UsageText: "step crypto nacl sign SUBCOMMAND [SUBCOMMAND_FLAGS]",
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
		Action:    cli.ActionFunc(signKeypairAction),
		Usage:     "generates a pair for use with sign and open",
		UsageText: "step crypto nacl sign keypair PUB_FILE PRIV_FILE",
	}
}

func signOpenCommand() cli.Command {
	return cli.Command{
		Name:      "open",
		Action:    cli.ActionFunc(signOpenAction),
		Usage:     "verifies a signed message produced by sign",
		UsageText: "step crypto nacl sign open PUB_FILE",
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
		Usage:     "signs a message using Ed25519",
		UsageText: "step crypto nacl sign sign PRIV_FILE",
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
		return errs.EqualArguments(ctx, "PUB_FILE", "PRIV_FILE")
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

	return nil
}

func signOpenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	pubFile := ctx.Args().Get(0)
	pub, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return errs.FileError(err, pubFile)
	} else if len(pub) != 32 {
		return errors.New("invalid public key: key size is not 32 bytes")
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
	priv, err := ioutil.ReadFile(privFile)
	if err != nil {
		return errs.FileError(err, privFile)
	} else if len(priv) != 64 {
		return errors.New("invalid private key: key size is not 64 bytes")
	}

	input, err := utils.ReadInput("Write text to sign: ")
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
