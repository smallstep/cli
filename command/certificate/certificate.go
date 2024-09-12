package certificate

import (
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
)

// Command returns the cli.Command for jwt and related subcommands.
func init() {
	cmd := cli.Command{
		Name:      "certificate",
		Usage:     "create, revoke, validate, bundle, and otherwise manage certificates",
		UsageText: "step certificate SUBCOMMAND [ARGUMENTS] [GLOBAL_FLAGS] [SUBCOMMAND_FLAGS]",
		Description: `**step certificate** command group provides facilities for creating
certificate signing requests (CSRs), creating self-signed certificates
(e.g., for use as a root certificate authority), generating leaf or
intermediate CA certificate by signing a CSR, validating certificates,
renewing certificates, generating certificate bundles, and key-wrapping
of private keys.

## EXAMPLES

Create a root certificate and private key using the default parameters (EC P-256 curve):
'''
$ step certificate create foo foo.crt foo.key --profile root-ca
'''

Create a leaf certificate and private key using the default parameters (EC P-256 curve):
'''
$ step certificate create baz baz.crt baz.key --ca ./foo.crt --ca-key ./foo.key
'''

Create a CSR and private key using the default parameters (EC P-256 curve):
'''
$ step certificate create zap zap.csr zap.key --csr
'''

Sign a CSR and generate a signed certificate:
'''
$ step certificate sign zap.csr foo.crt foo.key
'''

Inspect the contents of a certificate:
'''
$ step certificate inspect ./baz.crt
'''

Verify the signature of a certificate:
'''
$ step certificate verify ./baz.crt --roots ./foo.crt
'''

Lint the contents of a certificate to check for common errors and missing fields:
'''
$ step certificate lint ./baz.crt
'''

Bundle an end certificate with the issuing certificate:
'''
$ step certificate bundle ./baz.crt ./foo.crt bundle.crt
'''

Convert PEM format certificate to DER and write to disk.
'''
$ step certificate format foo.pem --out foo.der
'''

Extract the public key from a PEM encoded certificate:
'''
$ step certificate key foo.crt
'''

Install a root certificate in the system's default trust store:
'''
$ step certificate install root-ca.crt
'''

Uninstall a root certificate from the system's default trust store:
'''
$ step certificate uninstall root-ca.crt
'''`,

		Subcommands: cli.Commands{
			bundleCommand(),
			createCommand(),
			formatCommand(),
			inspectCommand(),
			fingerprintCommand(),
			lintCommand(),
			needsRenewalCommand(),
			signCommand(),
			verifyCommand(),
			keyCommand(),
			installCommand(),
			uninstallCommand(),
			p12Command(),
		},
	}

	command.Register(cmd)
}
