package nacl

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/utils"
)

func secretboxCommand() cli.Command {
	return cli.Command{
		Name:      "secretbox",
		Usage:     "encrypt and authenticate small messages using secret-key cryptography",
		UsageText: "step crypto nacl secretbox <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto nacl secretbox** command group uses secret-key cryptography to
encrypt, decrypt and authenticate messages. The implementation is based on NaCl's
crypto_secretbox function.

NaCl crypto_secretbox is designed to meet the standard notions of privacy and
authenticity for a secret-key authenticated-encryption scheme using nonces. For
formal definitions see, e.g., Bellare and Namprempre, "Authenticated encryption:
relations among notions and analysis of the generic composition paradigm,"
Lecture Notes in Computer Science 1976 (2000), 531–545,
https://eprint.iacr.org/2000/025.pdf. Note that the length is not
hidden. Note also that it is the caller's responsibility to ensure the
uniqueness of nonces—for example, by using nonce 1 for the first message, nonce
2 for the second message, etc. Nonces are long enough that randomly generated
nonces have negligible risk of collision.

By default nonces are alphanumeric, but it's possible to use binary nonces using
the prefix 'base64:' and the standard base64 encoding of the data, e.g.
'base64:081D3pFPBkwx1bURR9HQjiYbAUxigo0Z'. The prefix 'string:' is also
accepted, but it will be equivalent to not using a prefix. Nonces cannot be
longer than 24 bytes.

NaCl crypto_secretbox is crypto_secretbox_xsalsa20poly1305, a particular
combination of Salsa20 and Poly1305 specified in "Cryptography in NaCl". This
function is conjectured to meet the standard notions of privacy and
authenticity.

These commands are interoperable with NaCl: https://nacl.cr.yp.to/secretbox.html

## EXAMPLES

Encrypt a message using a 256-bit secret key, a new nacl box private key can
be used as the secret:
'''
$ step crypto nacl secretbox seal nonce secretbox.key
Please enter text to seal: ********
o2NJTsIJsk0dl4epiBwS1mM4xFED7iE

$ cat message.txt | step crypto nacl secretbox seal nonce secretbox.key
o2NJTsIJsk0dl4epiBwS1mM4xFED7iE
'''

Encrypt the message using a base64 nonce:
'''
$ cat message.txt | step crypto nacl secretbox seal base64:bm9uY2U= secretbox.key
o2NJTsIJsk0dl4epiBwS1mM4xFED7iE
'''

Decrypt and authenticate the message:
'''
$ echo o2NJTsIJsk0dl4epiBwS1mM4xFED7iE | step crypto nacl secretbox open nonce secretbox.key
message
'''`,
		Subcommands: cli.Commands{
			secretboxOpenCommand(),
			secretboxSealCommand(),
		},
	}
}

func secretboxOpenCommand() cli.Command {
	return cli.Command{
		Name:   "open",
		Action: cli.ActionFunc(secretboxOpenAction),
		Usage:  "authenticate and decrypt a box produced by seal",
		UsageText: `**step crypto nacl secretbox open** <nonce> <key-file>
[--raw]`,
		Description: `**step crypto nacl secretbox open** verifies and decrypts a ciphertext using a
secret key and a nonce.

This command uses an implementation of NaCl's crypto_secretbox_open function.

For examples, see **step help crypto nacl secretbox**.

## POSITIONAL ARGUMENTS

<nonce>
:  The nonce provided when the secretbox was sealed.

:  To use a binary nonce use the prefix 'base64:' and the standard base64
encoding. e.g. base64:081D3pFPBkwx1bURR9HQjiYbAUxigo0Z

<key-file>
:  The path to the shared key.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Indicates that input is not base64 encoded",
			},
		},
	}
}

func secretboxSealCommand() cli.Command {
	return cli.Command{
		Name:   "seal",
		Action: cli.ActionFunc(secretboxSealAction),
		Usage:  "produce an encrypted ciphertext",
		UsageText: `**step crypto nacl secretbox seal** <nonce> <key-file>
[--raw]`,
		Description: `**step crypto nacl secretbox seal** encrypts and authenticates a message using
a secret key and a nonce.

This command uses an implementation of NaCl's crypto_secretbox function.

For examples, see **step help crypto nacl secretbox**.

## POSITIONAL ARGUMENTS

<nonce>
:  Must be unique for each distinct message for a given key.

:  To use a binary nonce use the prefix 'base64:' and the standard base64
encoding. e.g. base64:081D3pFPBkwx1bURR9HQjiYbAUxigo0Z

<key-file>
:  The path to the shared key.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Do not base64 encode output",
			},
		},
	}
}

func secretboxOpenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, err := decodeNonce(args[0])
	if err != nil {
		return err
	}
	keyFile := args[1]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	key, err := os.ReadFile(keyFile)
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

	// Fixme: if we prepend the nonce in the seal we can use rawInput[24:]
	// as the message and rawInput[:24] as the nonce instead of requiring one.
	raw, ok := secretbox.Open(nil, rawInput, &n, &k)
	if !ok {
		return errors.New("error authenticating or decrypting input")
	}

	os.Stdout.Write(raw)
	return nil
}

func secretboxSealAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, err := decodeNonce(args[0])
	if err != nil {
		return err
	}
	keyFile := args[1]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return errs.FileError(err, keyFile)
	} else if len(key) != 32 {
		return errors.New("invalid key: key size is not 32 bytes")
	}

	input, err := utils.ReadInput("Please enter text to seal")
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
