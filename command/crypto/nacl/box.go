package nacl

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/nacl/box"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func boxCommand() cli.Command {
	return cli.Command{
		Name:      "box",
		Usage:     "authenticate and encrypt small messages using public-key cryptography",
		UsageText: "step crypto nacl box <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto nacl box** command group uses public-key cryptography to encrypt,
decrypt and authenticate messages. The implementation is based on NaCl's
crypto_box function.

NaCl crypto_box function is designed to meet the standard notions of
privacy and third-party unforgeability for a public-key authenticated-encryption
scheme using nonces. For formal definitions see, e.g., Jee Hea An,
"Authenticated encryption in the public-key setting: security notions and
analyzes," https://eprint.iacr.org/2001/079. Distinct messages between the same
(sender, receiver) set are required to have distinct nonces. For example, the
lexicographically smaller public key can use nonce 1 for its first message to
the other key, nonce 3 for its second message, nonce 5 for its third message,
etc., while the lexicographically larger public key uses nonce 2 for its first
message to the other key, nonce 4 for its second message, nonce 6 for its third
message, etc. Nonces are long enough that randomly generated nonces have
negligible risk of collision.

There is no harm in having the same nonce for different messages if the (sender,
receiver) sets are different. This is true even if the sets overlap. For example, a sender can use the same nonce for two different messages if the
messages are sent to two different public keys.

By default nonces are alphanumeric, but it's possible to use binary nonces using
the prefix 'base64:' and the standard base64 encoding of the data, e.g.
'base64:081D3pFPBkwx1bURR9HQjiYbAUxigo0Z'. The prefix 'string:' is also
accepted, but it will be equivalent to not using a prefix. Nonces cannot be
longer than 24 bytes.

NaCl crypto_box is not meant to provide non-repudiation. On the contrary: they
guarantee repudiability. A receiver can freely modify a boxed message, and
therefore cannot convince third parties that this particular message came from
the sender. The sender and receiver are nevertheless protected against forgeries
by other parties. In the terminology of
https://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c, NaCl crypto_box
uses "public-key authenticators" rather than "public-key signatures."

Users who want public verifiability (or receiver-assisted public verifiability)
should instead use signatures (or signcryption).

NaCl crypto_box is curve25519xsalsa20poly1305, a particular combination of
Curve25519, Salsa20, and Poly1305 specified in "Cryptography in NaCl". This
function is conjectured to meet the standard notions of privacy and third-party
unforgeability.

These commands are interoperable with NaCl: https://nacl.cr.yp.to/box.html

## EXAMPLES

Create a keypair for encrypting/decrypting messages:
'''
# Bob
$ step crypto nacl box keypair bob.box.pub bob.box.priv

# Alice
$ step crypto nacl box keypair alice.box.pub alice.box.priv
'''

Bob encrypts a message for Alice using her public key and signs it using his
private key:
'''
$ echo message | step crypto nacl box seal nonce alice.box.pub bob.box.priv
0oM0A6xIezA6iMYssZECmbMRQh77mzDt
'''

Alice receives the encrypted message and the nonce and decrypts with her
private key and validates the message from Bob using his public key:
'''
$ echo 0oM0A6xIezA6iMYssZECmbMRQh77mzDt | step crypto nacl box open nonce bob.box.pub alice.box.priv
message
'''

Decrypt the message using a base64 nonce:
'''
$ echo 0oM0A6xIezA6iMYssZECmbMRQh77mzDt | step crypto nacl box open base64:bm9uY2U= bob.box.pub alice.box.priv
message
'''`,
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
		Action:    command.ActionFunc(boxKeypairAction),
		Usage:     "generate a key for use with seal and open",
		UsageText: "**step crypto nacl box keypair** <pub-file> <priv-file>",
		Description: `Generates a new public/private keypair suitable for use with seal and open.
The private key is encrypted using a password in a nacl secretbox.

This command uses an implementation of NaCl's crypto_box_keypair function.

For examples, see **step help crypto nacl box**.

## POSITIONAL ARGUMENTS

<pub-file>
:  The path to write the public key.

<priv-file>
:  The path to write the encrypted private key.`,
		Flags: []cli.Flag{flags.Force},
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

This command uses an implementation of NaCl's crypto_box_open function.

For examples, see **step help crypto nacl box**.

## POSITIONAL ARGUMENTS

<nonce>
:  The nonce provided when the box was sealed.

:  To use a binary nonce use the prefix 'base64:' and the standard base64
encoding. e.g. base64:081D3pFPBkwx1bURR9HQjiYbAUxigo0Z

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

This command uses an implementation of NaCl's crypto_box function.

For examples, see **step help crypto nacl box**.

## POSITIONAL ARGUMENTS

<nonce>
:  Must be unique for each distinct message for a given pair of keys.

:  To use a binary nonce use the prefix 'base64:' and the standard base64
encoding. e.g. base64:081D3pFPBkwx1bURR9HQjiYbAUxigo0Z

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

	ui.Printf("Your public key has been saved in %s.\n", pubFile)
	ui.Printf("Your private key has been saved in %s.\n", privFile)
	return nil
}

func boxOpenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()
	nonce, err := decodeNonce(args[0])
	if err != nil {
		return err
	}
	pubFile, privFile := args[1], args[2]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	pub, err := os.ReadFile(pubFile)
	if err != nil {
		return errs.FileError(err, pubFile)
	} else if len(pub) != 32 {
		return errors.New("invalid public key: key size is not 32 bytes")
	}

	priv, err := os.ReadFile(privFile)
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

	// Fixme: if we prepend the nonce in the seal we can use rawInput[24:]
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
	nonce, err := decodeNonce(args[0])
	if err != nil {
		return err
	}
	pubFile, privFile := args[1], args[2]

	if len(nonce) > 24 {
		return errors.New("nonce cannot be longer than 24 bytes")
	}

	pub, err := os.ReadFile(pubFile)
	if err != nil {
		return errs.FileError(err, pubFile)
	} else if len(pub) != 32 {
		return errors.New("invalid public key: key size is not 32 bytes")
	}

	priv, err := os.ReadFile(privFile)
	if err != nil {
		return errs.FileError(err, privFile)
	} else if len(priv) != 32 {
		return errors.New("invalid private key: key size is not 32 bytes")
	}

	input, err := utils.ReadInput("Please enter text to seal")
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
