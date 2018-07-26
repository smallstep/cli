package nacl

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/auth"
)

func authCommand() cli.Command {
	return cli.Command{
		Name:      "auth",
		Usage:     "authenticates a message using a secret key",
		UsageText: "step crypto nacl auth <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto nacl auth** command group uses secret key cryptography to
authenticate and verify messages using a secret key.

TODO

## EXAMPLES

Authenticate a message using a 256-bit key, a new nacl box private key can be
used as the secret:
'''
$ step crypto nacl auth digest auth.key
Write text to authenticate: ********
33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1

$ cat message.txt | step crypto nacl auth digest auth.key
33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1
'''

Verify the message with the hash:
'''
$ step crypto nacl auth verify auth.key 33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1
Write text to verify: ********
ok

$ cat message.txt | step crypto nacl auth verify auth.key 33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1
ok
'''`,
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
		UsageText: "**step crypto nacl auth digest** <key-file>",
		Description: `**step crypto nacl auth digest** creates a digest to authenticate of a message
using a secret key.

TODO

For examples, see **step help crypto nacl auth**.`,
	}
}

func authVerifyCommand() cli.Command {
	return cli.Command{
		Name:      "verify",
		Action:    cli.ActionFunc(authVerifyAction),
		Usage:     "checks digest is a valid for a message",
		UsageText: "**step crypto nacl auth verify** <key-file> <digest>",
		Description: `**step crypto nacl auth verify** verifies the digest of a message with a secret
key.

TODO

For examples, see **step help crypto nacl auth**.`,
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

	input, err := utils.ReadInput("Write text to digest: ")
	if err != nil {
		return errors.Wrap(err, "error reading input")
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

	input, err := utils.ReadInput("Write text to verify: ")
	if err != nil {
		return errors.Wrap(err, "error reading input")
	}

	var k [32]byte
	copy(k[:], key)

	if auth.Verify(sum, input, &k) {
		fmt.Println("ok")
		return nil
	}

	return errors.New("fail")
}
