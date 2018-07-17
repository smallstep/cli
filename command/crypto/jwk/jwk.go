package jwk

import "github.com/urfave/cli"

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "jwk",
		Usage:     "create JWKs (JSON Web Keys) and manage JWK Key Sets",
		UsageText: "step crypto jwk SUBCOMMAND [ARGUMENTS] [GLOBAL_FLAGS] [SUBCOMMAND_FLAGS]",
		Description: `The **step crypto jwk** command group provides facilities for creating JWKs
(JSON Web Keys) as defined in RFC7517. It also includes command line utilities
for managing Key Sets and working with encrypted keys.

  A JWK is a JSON data structure that represents a cryptographic key. The
members of this data structure represent properties of the key, including its
value. A JWK Set is a simple data structure for representing a set of JWKs. A
JWK Set is a JSON object with a "keys" member whose value is an array of JWKs.
Cryptographic algorithms and identifiers for used by JWKs are defined by the
JSON Web Algorithms (JWA) specification in RFC7518. This tool also supports
extensions defined in standards track RFC8037 defining curve and algorithm
identifiers for Edwards-curve Digial Signatures.

  JWKs and JWK Sets are used in the JSON Web Signature (JWS; RFC7515) and JSON
Web Encryption (JWE; RFC7516) specifications for signing and encrypting JSON
data, respectively.`,
		Subcommands: cli.Commands{
			createCommand(),
			keysetCommand(),
			publicCommand(),
			thumbprintCommand(),
		},
	}
}
