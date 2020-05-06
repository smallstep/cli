package nacl

import (
	"encoding/base64"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

// Command returns the cli.Command for nacl and related subcommands.
func Command() cli.Command {
	return cli.Command{
		Name:      "nacl",
		Usage:     "easy-to-use high-speed tools for encryption and signing",
		UsageText: "step crypto nacl <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `The **step crypto nacl** command group is a thin CLI wrapper around the NaCl
(pronounced "salt") cryptography library. NaCl's goal is to provide all of the
core operations needed to build higher-level cryptographic tools.

Perhaps its biggest advantage is simplicity. NaCl was designed to be easy to
use and hard to misuse. Typical cryptographic libraries force you to specify
choices for cryptographic primitives and constructions (e.g., sign this
message with 4096-bit RSA using PKCS#1 v2.0 with SHA-256). But most people are
not cryptographers. These choices become foot guns. By contrast, NaCl allows
you to simply say "sign this message". NaCl ships with a preselected choice --
a state-of-the-art signature system suitable for most applications -- and it
has a side mechanism through which a cryptographer can easily override the
choice of signature system.

There are language bindings and pure implementations of NaCl for all major
languages. For internal use cases where compatibility with open standards like
JWT are not an issue, NaCl should be your default choice for cryptographic
needs.

For more information on NaCl visit https://nacl.cr.yp.to`,
		Subcommands: cli.Commands{
			authCommand(),
			boxCommand(),
			secretboxCommand(),
			signCommand(),
		},
	}
}

var b64Encoder = base64.RawURLEncoding

// decodeNonce returns the nonce in bytes. If the input has the prefix base64:
// it will decode the rest using the base64 standard encoding.
func decodeNonce(in string) ([]byte, error) {
	nonce := []byte(in)
	switch {
	case strings.HasPrefix(in, "string:"):
		return nonce[7:], nil
	case strings.HasPrefix(in, "base64:"):
		input := nonce[7:]
		nonce = make([]byte, base64.StdEncoding.DecodedLen(len(input)))
		n, err := base64.StdEncoding.Decode(nonce, input)
		if err != nil {
			return nil, errors.Wrap(err, "error decoding base64 nonce")
		}
		return nonce[:n], nil
	default:
		return nonce, nil
	}
}
