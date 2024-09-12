package crypto

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"

	"github.com/smallstep/cli/command/crypto/hash"
	"github.com/smallstep/cli/command/crypto/jose"
	"github.com/smallstep/cli/command/crypto/jwe"
	"github.com/smallstep/cli/command/crypto/jwk"
	"github.com/smallstep/cli/command/crypto/jws"
	"github.com/smallstep/cli/command/crypto/jwt"
	"github.com/smallstep/cli/command/crypto/kdf"
	"github.com/smallstep/cli/command/crypto/key"
	"github.com/smallstep/cli/command/crypto/nacl"
	"github.com/smallstep/cli/command/crypto/otp"
	"github.com/smallstep/cli/command/crypto/rand"
	"github.com/smallstep/cli/command/crypto/winpe"
)

func init() {
	cmd := cli.Command{
		Name:  "crypto",
		Usage: "useful cryptographic plumbing",
		Description: `The **step crypto** command group provides a selection of useful cryptographic
primitives that balances completeness and safety (cryptographic strength, ease
of use, and misuse prevention). Subcommands include flags and arguments to
select algorithms and fine-tune behaviors, but we've selected safe defaults for
you wherever possible.

Insecure or subtle cryptographic primitives and options are gated with flags to
prevent accidental misuse. Such primitives and options will not work unless you
pass the corresponding flags to indicate that you understand the risks
(**--insecure** and **--subtle**, respectively). Our rationale for these
decisions is usually documented in the **SECURITY CONSIDERATIONS** section of
the help for each subcommand.

## SECURITY CONSIDERATIONS

The strength of cryptographic mechanisms depends on the strength of all links
in the security chain. This includes the quality and strength of algorithms,
random number generation, distribution mechanisms, etc. It also includes
protection against hostile observation and tampering as well as the security of
the overall system including the operating system and personnel, etc. Where
possible, we've selected secure defaults. Whenever a subtle or insecure
cryptographic operation is attempted affirmative confirmation via prompt or
command line flag is required, indicating that you understand and accept the
risks. That said, many of these factors are beyond the scope of this tool.

**Key Length**

:  This tool enforces a minimum key size of **256 bits for symmetric keys**, which is
   generally considered quantum-safe and accepted as sufficient for the
   foreseeable future.

:  This tool enforces the NIST recommended minimum key size of **2048 bits for RSA**
   keys, which RSA claims is equivalent in strength to 112 bit symmetric keys and
   is likely to be sufficient until 2030. An RSA key length of at least 3072 bits,
   which RSA claims is equivalent to 128 bit symmetric keys, should be used if
   security is required beyond 2030.

:  Elliptic curve cryptography is generally believed to be secure with shorter
   keys than RSA requires. NIST guidelines state that ECC keys should be twice the
   length of the equivalent strength symmetric key. The rough equivalencies for
   the elliptic curves supported by this tool are:

:  | key type | curve   | RSA equivalent | symmetric key equivalent |
   |----------|---------|----------------|--------------------------|
   | EC       | P-256   | ~3000 bits     | ~128 bits                |
   | EC       | P-384   | ~4096 bits     | ~192 bits                |
   | EC       | P-521   | ~15000 bits    | ~256 bits                |
   | OKP      | Ed25519 | ~3000 bits     | ~140 bits                |

:  Elliptic curve cryptography has the additional advantages of much smaller key
   sizes for equivalent security levels, and much faster cryptographic operations
   compared to RSA. The strength of these keys is generally considered sufficient
   for the predictable and foreseeable future.

:  Note that for cryptographic protocols that have perfect forward secrecy and
   only use asymmetric keys for symmetric key negotiation your system will remain
   secure against future threats as long as the keys are large enough that they
   cannot be cracked today. In other words, sizing your keys to protect against
   potential future threats is largely irrelevant.

**Key Use**

:  In general you should not use an asymmetric keypair for both signing and
   encryption. Using a single key for both operations can introduce attack vectors
   that would not otherwise exist. Attacks aside, signing keys and encryption
   keys generally have different life cycles. Signing keys are generally destroyed
   once they're no longer useful for singing new data. Encryption keys, on the
   other hand, must be retained as long as data exists that was encrypted for the
   key. So using a signing key for encryption may force you to retain a signing
   key for longer than it's needed, leaving it susceptible to misuse.

:  Raw public or private keys don't have any associated data, therefore this
   tool cannot enforce key use on raw keys and this responsibility is up to
   you. For keys in an "envelope" the envelope typically includes key use
   restrictions (e.g., the "use" parameter in JWKs and the "Key Usage"
   attribute of X.509 certificates). This tool generally requires key use to be
   specified when creating an enveloped key, and enforces key use restrictions
   when an enveloped key is being used.

**Safe Curves**

:  There is some concern that certain standard elliptic curves are very hard to
   implement correctly. These concerns are not purely theoretical. Implementation
   issues have been uncovered and real attacks have been demonstrated.

:  While we take these concerns seriously, these curves are widely used in
   practice, largely because they are perceived to be stronger than RSA and have
   been implemented in more places than the "safe curves". Therefore, **we've
   opted not to gate non-safe curves**. We've further elected to make **P-256**
   the default curve for EC keys.

:  Still, it is important to be aware of the security risks associated with their
   risk. You should consider using "safe curves" if possible. We may change our
   mind as support for safe curves improves.

: Safe and non-safe curves implemented by this tool are:

:  | key type | curve   | safe |
   |----------|---------|------|
   | EC       | P-256   | NO   |
   | EC       | P-384   | NO   |
   | EC       | P-521   | NO   |
   | OKP      | Ed25519 | YES  |

:  For more information see https://safecurves.cr.yp.to/

**Quantum Safety**

:  Quantum-safe cryptography refers to keys and algorithms that are secure against
   an attack by a quantum computer. As of 2018 most public key algorithms are not
   quantum safe. In particular, **none of the public key algorithms implemented by
   this tool are quantum safe**. However, no quantum computer exists that is
   powerful enough to break current algorithms. Using cryptographic protocols with
   forward secrecy is the best way to protect against future quantum attacks.

**Forward Secrecy**

:  A cryptosystem or protocol has forward secrecy (or perfect forward secrecy) if,
   for each session or interaction, a random key is generated such that an
   attacker with access to all private keys would still not know the generated
   key. This can be accomplished using Diffie-Hellman key exchange, for instance.

:  Forward secrecy can protect against an attacker who stores intercepted
   communication and waits for your private key to be compromised, at which point
   they could decrypt the stored communication. It also offers good protection
   against quantum attacks since symmetric key cryptosystems like AES are already
   considered quantum resistant with sufficiently large key sizes. The current
   best quantum attack against symmetric key systems requires work proportional to
   the square of the size of the key space. In other words, a symmetric key is
   half as strong against a quantum attack vs. a conventional attack, so your key
   needs to be twice as long for equivalent quantum-safe security. A 256 bit
   symmetric key in the context of a quantum attack is equivalent in strength to a
   128 bit key in the context of a conventional attack.
`,
		Subcommands: cli.Commands{
			changePassCommand(),
			createKeyPairCommand(),
			jwk.Command(),
			jwt.Command(),
			jwe.Command(),
			jws.Command(),
			jose.Command(),
			hash.Command(),
			kdf.Command(),
			key.Command(),
			nacl.Command(),
			otp.Command(),
			rand.Command(),
			winpe.Command(),
		},
	}

	command.Register(cmd)
}
