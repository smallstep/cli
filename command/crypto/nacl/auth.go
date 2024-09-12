package nacl

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/auth"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/utils"
)

func authCommand() cli.Command {
	return cli.Command{
		Name:      "auth",
		Usage:     "authenticate a message using a secret key",
		UsageText: "step crypto nacl auth <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto nacl auth** command group uses secret key cryptography to
authenticate and verify messages using a secret key. The implementation is based on NaCl's
crypto_auth function.

NaCl crypto_auth function, viewed as a function of the message for a uniform
random key, is designed to meet the standard notion of unforgeability. This
means that an attacker cannot find authenticators for any messages not
authenticated by the sender, even if the attacker has adaptively influenced the
messages authenticated by the sender. For a formal definition see, e.g., Section
2.4 of Bellare, Kilian, and Rogaway, "The security of the cipher block chaining
message authentication code," Journal of Computer and System Sciences 61 (2000),
362–399; https://cseweb.ucsd.edu/~mihir/papers/cbc.pdf.

NaCl crypto_auth does not make any promises regarding "strong" unforgeability;
perhaps one valid authenticator can be converted into another valid
authenticator for the same message. NaCl auth also does not make any promises
regarding "truncated unforgeability."

NaCl crypto_auth is currently an implementation of HMAC-SHA-512-256, i.e., the
first 256 bits of HMAC-SHA-512. HMAC-SHA-512-256 is conjectured to meet the
standard notion of unforgeability.

These commands are interoperable with NaCl: https://nacl.cr.yp.to/auth.html

## EXAMPLES

Authenticate a message using a 256-bit key, a new nacl box private key can be
used as the secret:
'''
$ step crypto nacl auth digest auth.key
Please enter text to authenticate: ********
33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1

$ cat message.txt | step crypto nacl auth digest auth.key
33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1
'''

Verify the message with the hash:
'''
$ step crypto nacl auth verify auth.key 33c54aeb54077808fcfccadcd2f01971b120e314dffa61516b0738b74fdc8ff1
Please enter text to verify: ********
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
		Usage:     "generate a 32-byte digest for a message",
		UsageText: "**step crypto nacl auth digest** <key-file>",
		Description: `**step crypto nacl auth digest** creates a digest to authenticate the message
is read from STDIN using the given secret key.

This command uses an implementation of NaCl's crypto_auth function.

For examples, see **step help crypto nacl auth**.`,
	}
}

func authVerifyCommand() cli.Command {
	return cli.Command{
		Name:      "verify",
		Action:    cli.ActionFunc(authVerifyAction),
		Usage:     "validate a digest for a message",
		UsageText: "**step crypto nacl auth verify** <key-file> <digest>",
		Description: `**step crypto nacl auth verify** checks that the digest is a valid authenticator
of the message is read from STDIN under the given secret key file.

This command uses an implementation of NaCl's crypto_auth_verify function.

For examples, see **step help crypto nacl auth**.`,
	}
}

func authDigestAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	keyFile := ctx.Args().Get(0)

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != auth.KeySize {
		return errors.Errorf("invalid key file: key size is not %d bytes", auth.KeySize)
	}

	input, err := utils.ReadInput("Please enter text to digest")
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

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != auth.KeySize {
		return errors.Errorf("invalid key file: key size is not %d bytes", auth.KeySize)
	}

	sum, err := hex.DecodeString(digest)
	if err != nil {
		return errors.Wrap(err, "error decoding digest")
	}

	input, err := utils.ReadInput("Please enter text to verify")
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
