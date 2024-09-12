package kdf

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/kdf"
	"github.com/smallstep/cli/utils"
)

// Command returns the cli.Command for kdf and related subcommands.
func Command() cli.Command {
	return cli.Command{
		Name:      "kdf",
		Usage:     "key derivation functions for password hashing and verification",
		UsageText: "step crypto kdf <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto kdf** command group creates and verifies passwords using key
derivation functions.

## EXAMPLES

Derive a password using **scrypt**:
'''
$ step crypto kdf hash
Enter password to hash: ********
$scrypt$ln=15,r=8,p=1$3TCG+xs8HWSIHonnqTp6Xg$UI8CYfz6koUaRMjDWEFgujIxM63fYnAcc0HhpUryFn8

$ step crypto kdf hash --insecure password
$scrypt$ln=15,r=8,p=1$U8Fl1sO6LWkFeXs5GQS0vA$Rj8nPeaBFQUzbU21N+hhm3I/s1WTxao7Dje4G6ZvO9Q
'''

Derive a password using **bcrypt**:
'''
$ step crypto kdf hash --alg bcrypt
Enter password to hash: ********
$2a$10$EgTYeokp/EhvlMpaDYX56O67M/Ve4JyTl9DHwailYYFOBT3COSTuy

$ step crypto kdf hash --alg bcrypt --insecure password
$2a$10$kgYs5dEKs2C6Y5PXnU7eTuPzHMeSoCnkvtTL7ghsPDdSSmw5ec/sS
'''

Derive a password using **argon2i**:
'''
$ step crypto kdf hash --alg argon2i
Enter password to hash: ********
$argon2i$v=19$m=32768,t=3,p=4$H0IxAhFFO7fOu5K2RYTxxA$ULEz/79vh3BtCcm7W/zRfJSpiEGULirrZ+PnHfspWKA
'''

Derive a password using **argon2id**:
'''
$ step crypto kdf hash --alg argon2id
Enter password to hash: ********
$argon2id$v=19$m=65536,t=1,p=4$HDi5gI15NwJrKveh2AAa9Q$30haKRwwUe5I4WfkPZPGmhJKTRTO+98x+sVnHhOHdK8
'''

Validate a hash:
'''
$ step crypto kdf compare '$scrypt$ln=15,r=8,p=1$3TCG+xs8HWSIHonnqTp6Xg$UI8CYfz6koUaRMjDWEFgujIxM63fYnAcc0HhpUryFn8'
Enter password to compare: ********
ok

$ step crypto kdf compare --insecure '$scrypt$ln=15,r=8,p=1$3TCG+xs8HWSIHonnqTp6Xg$UI8CYfz6koUaRMjDWEFgujIxM63fYnAcc0HhpUryFn8' password
ok

$ step crypto kdf compare '$2a$10$EgTYeokp/EhvlMpaDYX56O67M/Ve4JyTl9DHwailYYFOBT3COSTuy'
Enter password to compare: ********
ok

$ step crypto kdf compare --insecure '$2a$10$EgTYeokp/EhvlMpaDYX56O67M/Ve4JyTl9DHwailYYFOBT3COSTuy' password
ok

$ step crypto kdf compare '$argon2i$v=19$m=32768,t=3,p=4$H0IxAhFFO7fOu5K2RYTxxA$ULEz/79vh3BtCcm7W/zRfJSpiEGULirrZ+PnHfspWKA'
Enter password to compare: ********
ok

$ step crypto kdf compare --insecure '$argon2i$v=19$m=32768,t=3,p=4$H0IxAhFFO7fOu5K2RYTxxA$ULEz/79vh3BtCcm7W/zRfJSpiEGULirrZ+PnHfspWKA' password
ok

$ step crypto kdf compare --insecure '$argon2id$v=19$m=65536,t=1,p=4$HDi5gI15NwJrKveh2AAa9Q$30haKRwwUe5I4WfkPZPGmhJKTRTO+98x+sVnHhOHdK8'
Enter password to compare: ********
ok

$ step crypto kdf compare --insecure '$argon2id$v=19$m=65536,t=1,p=4$HDi5gI15NwJrKveh2AAa9Q$30haKRwwUe5I4WfkPZPGmhJKTRTO+98x+sVnHhOHdK8' password
ok
'''`,
		Subcommands: cli.Commands{
			hashCommand(),
			compareCommand(),
		},
	}
}

func hashCommand() cli.Command {
	return cli.Command{
		Name:   "hash",
		Action: cli.ActionFunc(hashAction),
		Usage:  "derive a secret key from a secret value (e.g., a password)",
		UsageText: `**step crypto kdf hash** [<input>]
[--alg ALGORITHM]`,
		Description: `**step crypto kdf hash** uses a key derivation function (KDF) to produce a
pseudorandom secret key based on some (presumably secret) input value. This is
useful for password verification approaches based on password hashing. Key
derivation functions are designed to be computationally intensive, making it
more difficult for attackers to perform brute-force attacks on password
databases.

If this command is run without the optional <input> argument and STDIN is a TTY
(i.e., you're running the command in an interactive terminal and not piping
input to it) you'll be prompted to enter a value on STDERR. If STDIN is not a
TTY it will be read without prompting.

This command will produce a string encoding of the KDF output along with the
algorithm used, salt, and any parameters required for validation in PHC string
format.

The KDFs are run with parameters that are considered safe. The 'scrypt'
parameters are currently fixed at N=32768, r=8 and p=1. The 'bcrypt' work
factor is currently fixed at 10.

For examples, see **step help crypto kdf**.

## POSITIONAL ARGUMENTS

<input>
:  The input to the key derivation function. <input> is optional and its use is
not recommended. If this argument is provided the **--insecure** flag must also
be provided because your (presumably secret) <input> will likely be logged and
appear in places you might not expect. If omitted input is read from STDIN.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "alg",
				Value: "scrypt",
				Usage: `The KDF algorithm to use.

:  <algorithm> must be one of:

		**scrypt**
		:  A password-based KDF designed to use exponential time and memory.

		**bcrypt**
		:  A password-based KDF designed to use exponential time.

		**argon2i**
		: A password-based KDF optimized to resist side-channel attacks.

		**argon2id**
		: A password-based KDF optimized to resist GPU and side-channel attacks.
`,
			},
			flags.InsecureHidden,
		},
	}
}

func hashAction(ctx *cli.Context) error {
	var err error
	var input []byte

	// Get kdf method
	var f kdf.KDF
	switch alg := ctx.String("alg"); alg {
	case "scrypt":
		f = kdf.Scrypt
	case "bcrypt":
		f = kdf.Bcrypt
	case "argon2i":
		f = kdf.Argon2i
	case "argon2id":
		f = kdf.Argon2id
	default:
		return errs.InvalidFlagValue(ctx, "alg", alg, "")
	}

	// Grab input from terminal or arguments
	switch ctx.NArg() {
	case 0:
		input, err = utils.ReadInput("Please enter the password to hash")
		if err != nil {
			return err
		}
	case 1:
		if !ctx.Bool("insecure") {
			return errs.InsecureArgument(ctx, "INPUT")
		}
		input = []byte(ctx.Args().Get(0))
	default:
		return errs.TooManyArguments(ctx)
	}

	// Hash input
	hash, err := f(input)
	if err != nil {
		return err
	}

	fmt.Println(hash)
	return nil
}

func compareCommand() cli.Command {
	return cli.Command{
		Name:      "compare",
		Action:    cli.ActionFunc(compareAction),
		Usage:     "compare a plaintext value (e.g., a password) and a hash",
		UsageText: "step crypto kdf compare <phc-hash> [<input>]",
		Description: `The 'step crypto kdf compare' command compares a plaintext value (e.g., a
password) with an existing KDF password hash in PHC string format. The PHC
string input indicates which KDF algorithm and parameters to use.

  If the input matches <phc-hash> the command prints a human readable message
indicating success to STDERR and returns 0. If the input does not match an
error will be printed to STDERR and the command will exit with a non-zero
return code.

  If this command is run without the optional <input> argument and STDIN is a
TTY (i.e., you're running the command in an interactive terminal and not
piping input to it) you'll be prompted to enter a value on STDERR. If STDIN is
not a TTY it will be read without prompting.

For examples, see **step help crypto kdf**.

POSITIONAL ARGUMENTS

<phc-hash>
:  The KDF password hash in PHC string format.

<input>
:  The plaintext value to compare with <phc-hash>. <input> is optional and its
use is not recommended. If this argument is provided the **--insecure** flag
must also be provided because your (presumably secret) <input> will likely be
logged and appear in places you might not expect. If omitted input is read
from STDIN.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
		},
	}
}

func compareAction(ctx *cli.Context) error {
	var err error
	var input, hash []byte

	switch ctx.NArg() {
	case 0:
		return errs.MissingArguments(ctx, "PHC_HASH")
	case 1:
		hash = []byte(ctx.Args().Get(0))
		input, err = utils.ReadInput("Please enter the password to compare")
		if err != nil {
			return err
		}
	case 2:
		if !ctx.Bool("insecure") {
			return errs.InsecureArgument(ctx, "INPUT")
		}
		args := ctx.Args()
		hash, input = []byte(args[0]), []byte(args[1])
	default:
		return errs.TooManyArguments(ctx)
	}

	ok, err := kdf.Compare(input, hash)
	if err != nil {
		return err
	}

	if ok {
		fmt.Println("ok")
		return nil
	}
	return errors.New("fail")
}
