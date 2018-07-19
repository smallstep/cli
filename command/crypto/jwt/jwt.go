package jwt

import (
	"github.com/urfave/cli"
)

// Command returns the cli.Command for jwt and related subcommands.
func Command() cli.Command {
	return cli.Command{
		Name:      "jwt",
		Usage:     "sign and verify data using JSON Web Tokens (JWT)",
		UsageText: "step crypto jwt <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `A JSON Web Token or JWT (pronounced "jot") is a compact data structure used
to represent some JSON encoded "claims" that are passed as the payload of a
JWS or JWE structure, enabling the claims to be digitally signed and/or
encrypted. The "claims" (or "claim set") are represented as an ordinary JSON
object. JWTs are represented using a compact format that's URL safe and can be
used in space-constrained environments. JWTs can be passed in HTTP
Authorization headers and as URI query parameters.

A "claim" is a piece of information asserted about a subject, represented as a
key/value pair. Logically a verified JWT can be interpreted as "<issuer> says to
<audience> that <subject>'s <claim-name> is <claim-value>" for each claim.

A JWT signed using JWS has three parts:

    1. A base64 encoded JSON object representing the JOSE (JSON Object Signing
       and Encryption) header that describes the cryptographic operations
       applied to the JWT Claims Set
    2. A base64 encoded JSON object representing the JWT Claims Set
    3. A base64 encoded digital signature of message authentication code`,
		Subcommands: cli.Commands{
			signCommand(),
			verifyCommand(),
			inspectCommand(),
		},
	}
}
