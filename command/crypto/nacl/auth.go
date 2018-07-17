package nacl

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/smallstep/cli/errs"

	"github.com/smallstep/cli/command/crypto/internal/utils"
	"golang.org/x/crypto/nacl/auth"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

func authCommand() cli.Command {
	return cli.Command{
		Name:      "auth",
		Usage:     "authenticates a message using a secret key",
		UsageText: "step crypto nacl auth SUBCOMMAND [SUBCOMMAND_FLAGS]",
		Subcommands: cli.Commands{
			authDigestCommand(),
			authVerifyCommand(),
		},
	}
}

func authDigestCommand() cli.Command {
	return cli.Command{
		Name:      "digest",
		Action:    cli.ActionFunc(authDigestAction),
		Usage:     "generates a 32-byte digest for a message",
		UsageText: "step crypto nacl auth digest KEY_FILE",
	}
}

func authVerifyCommand() cli.Command {
	return cli.Command{
		Name:      "verify",
		Action:    cli.ActionFunc(authVerifyAction),
		Usage:     "checks digest is a valid for a message",
		UsageText: "step crypto nacl auth verify KEY_FILE DIGEST",
	}
}

func authDigestAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	keyFile := ctx.Args().Get(0)

	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != auth.KeySize {
		return errors.Errorf("invalid key file: key size is not %d bytes", auth.KeySize)
	}

	input, err := utils.ReadAll(os.Stdin)
	if err != nil {
		return errs.Wrap(err, "error reading from STDIN")
	}

	var k [32]byte
	copy(k[:], key)

	sum := auth.Sum(input, &k)
	fmt.Println(hex.EncodeToString(sum[:]))
	return nil
}

func authVerifyAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	keyFile, digest := args[0], args[1]

	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != auth.KeySize {
		return errors.Errorf("invalid key file: key size is not %d bytes", auth.KeySize)
	}

	sum, err := hex.DecodeString(digest)
	if err != nil {
		return errors.Wrap(err, "error decoding digest")
	}

	input, err := utils.ReadAll(os.Stdin)
	if err != nil {
		return errs.Wrap(err, "error reading from STDIN")
	}

	var k [32]byte
	copy(k[:], key)

	if auth.Verify(sum, input, &k) {
		fmt.Println("ok")
		return nil
	}

	return errors.New("fail")
}
