package key

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"golang.org/x/crypto/ssh"
)

func fingerprintCommand() cli.Command {
	return cli.Command{
		Name:      "fingerprint",
		Action:    command.ActionFunc(fingerprintAction),
		Usage:     `print the fingerprint of a public key`,
		UsageText: `**step crypto key fingerprint** <key-file>`,
		Description: `**step crypto key fingerprint** prints the fingerprint of a public key. The
fingerprint of a private key will be only based on the public part of the
key.

By default the fingerprint calculated is the SHA-256 hash with raw Base64 encoding
of the ASN.1 BIT STRING of the subjectPublicKey defined in RFC 5280.

Using the flag **--ssh** the fingerprint would be based on the SSH encoding of
the public key.

Note that for certificates and certificate request, the fingerprint would be
based only on the public key embedded in the certificate. To get the certificate
fingerprint use the appropriate commands:

'''
$ step certificate fingerprint <x509-crt|x509-csr>
$ step ssh fingerprint <ssh-crt>
'''

## POSITIONAL ARGUMENTS

<key-file>
:  Path to a public, private key, certificate (X.509 and SSH) or
   certificate request.

## EXAMPLES

Print the fingerprint of a public key:
'''
$ step crypto key fingerprint pub.pem
'''

Print the fingerprint of the public key using the SSH marshaling:
'''
$ step crypto key fingerprint --ssh pub.pem
'''

Print the fingerprint of the key embedded in a certificate using the SHA-1 hash:
'''
$ step crypto key fingerprint --sha1 cert.pem
'''

Print the same fingerprint for a public key, a private key and a
certificate all of with the same public key.
'''
$ step crypto key fingerprint id_ed25519
$ step crypto key fingerprint id_ed25519.pub
$ step crypto key fingerprint id_ed25519-cert.pub
'''

Print the fingerprint of the key using an external tool:
'''
$ step crypto key fingerprint --raw pub.pem | md5sum
'''

Print the fingerprint of the public key of an encrypted private key:
'''
$ step crypto key fingerprint --password-file pass.txt priv.pem
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "sha1",
				Usage: "Use the SHA-1 hash with hexadecimal format. The result will be equivalent to the Subject Key Identifier in a X.509 certificate.",
			},
			cli.BoolFlag{
				Name:  "ssh",
				Usage: "Use the SSH marshaling format instead of X.509.",
			},
			cli.StringFlag{
				Name:  "password-file",
				Usage: "The path to the <file> containing passphrase to decrypt a private key.",
			},
			cli.BoolFlag{
				Name:  "raw",
				Usage: "Print the raw bytes instead of the fingerprint. These bytes can be piped to a different hash command.",
			},
		},
	}
}

func fingerprintAction(ctx *cli.Context) error {
	if err := errs.MinMaxNumberOfArguments(ctx, 0, 1); err != nil {
		return err
	}

	var name string
	switch ctx.NArg() {
	case 0:
		name = "-"
	case 1:
		name = ctx.Args().First()
	default:
		return errs.TooManyArguments(ctx)
	}

	b, err := utils.ReadFile(name)
	if err != nil {
		return err
	}

	var key interface{}
	switch {
	case bytes.HasPrefix(b, []byte("-----BEGIN ")): // PEM format:
		opts := []pemutil.Options{
			pemutil.WithFilename(name),
			pemutil.WithFirstBlock(),
		}
		if passFile := ctx.String("password-file"); passFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(passFile))
		}
		if key, err = pemutil.ParseKey(b, opts...); err != nil {
			return err
		}
	case isSSHPublicKey(b):
		if key, err = pemutil.ParseSSH(b); err != nil {
			return err
		}
	case isJWK(b):
		if key, err = parseJWK(ctx, b); err != nil {
			return err
		}
	default: // assuming DER format
		if key, err = pemutil.ParseDER(b); err != nil {
			return err
		}
	}

	if k, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		key = k.Public()
	}

	if ctx.Bool("ssh") {
		b, err = sshFingerprintBytes(key)
	} else {
		b, err = x509FingerprintBytes(key)
	}
	if err != nil {
		return err
	}

	switch {
	case ctx.Bool("raw"):
		os.Stdout.Write(b)
	case ctx.Bool("sha1"):
		sum := sha1.Sum(b)
		fmt.Printf("SHA1:%x\n", sum[:])
	default:
		sum := sha256.Sum256(b)
		fmt.Println("SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]))
	}

	return nil
}

// subjectPublicKeyInfo is a PKIX public key structure defined in RFC 5280.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func x509FingerprintBytes(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling public key")
	}
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling public key")
	}
	return info.SubjectPublicKey.Bytes, nil
}

func sshFingerprintBytes(pub crypto.PublicKey) ([]byte, error) {
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "error creating ssh public key")
	}
	return key.Marshal(), nil
}
