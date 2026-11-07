package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certinfo"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/truststore"
	"go.step.sm/crypto/pemutil"
)

func installCommand() cli.Command {
	return cli.Command{
		Name:   "install",
		Action: command.ActionFunc(installAction),
		Usage:  "install a root certificate in the supported trust stores",
		UsageText: `**step certificate install** <crt-file>
[**--prefix**=<name>] [**--all**]
[**--java**] [**--firefox**] [**--no-system**]`,
		Description: `**step certificate install** installs a root certificate in
the supported trust stores.

Java's and Firefox's trust stores are also supported via the respective flags

## POSITIONAL ARGUMENTS

<crt-file>
:  Root certificate to install in the specified trust stores.

## EXAMPLES

Install a root certificate in the system's default trust store:
'''
$ step certificate install root-ca.pem
'''

Install a root certificate in all the supported trust stores:
'''
$ step certificate install --all root-ca.pem
'''

Install a root certificate in Firefox's and the system's default trust store:
'''
$ step certificate install --firefox root-ca.pem
'''

Install a root certificate in Java's and the system's default trust store:
'''
$ step certificate install --java root-ca.pem
'''

Install a root certificate in Firefox's and Java's trust store, but not in the system's default trust store:
'''
$ step certificate install --firefox --java --no-system root-ca.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "prefix",
				Usage: `The prefix used to <name> the CA in the trust store. Defaults to the
certificate common name.`,
			},
			cli.BoolFlag{
				Name:  "java",
				Usage: "install on the Java key store",
			},
			cli.BoolFlag{
				Name:  "firefox",
				Usage: "install on the Firefox NSS security database",
			},
			cli.BoolFlag{
				Name:  "no-system",
				Usage: "disables the install on the system's default trust store",
			},
			cli.BoolFlag{
				Name:  "all",
				Usage: "install in Firefox's, Java's, and the system's default trust store",
			},
		},
	}
}

func uninstallCommand() cli.Command {
	return cli.Command{
		Name:   "uninstall",
		Action: command.ActionFunc(uninstallAction),
		Usage:  "uninstall a root certificate from the supported trust stores",
		UsageText: `**step certificate uninstall** <crt-file>
[**--prefix**=<name>] [**--all**]
[**--java**] [**--firefox**] [**--no-system**]`,
		Description: `**step certificate uninstall** uninstalls a root certificate from
the supported trust stores.

Java's and Firefox's trust stores are also supported via the respective flags.

## POSITIONAL ARGUMENTS

<crt-file>
:  Root certificate to uninstall from the specified trust stores.

## EXAMPLES

Uninstall only from the system's default trust store:
'''
$ step certificate uninstall root-ca.pem
'''

Uninstall a root certificate from all the supported trust stores:
'''
$ step certificate uninstall --all root-ca.pem
'''

Uninstall a root certificate from Firefox's and the system's default trust store:
'''
$ step certificate uninstall --firefox root-ca.pem
'''

Uninstall a root certificate from Java's and the system's default trust store:
'''
$ step certificate uninstall --java root-ca.pem
'''

Uninstall a certificate from Firefox, Java, but not from the system:
'''
$ step certificate uninstall --firefox --java --no-system root-ca.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "prefix",
				Usage: `The prefix used to <name> the CA in the trust store. Defaults to the
certificate common name.`,
			},
			cli.BoolFlag{
				Name:  "java",
				Usage: "uninstall from the Java key store",
			},
			cli.BoolFlag{
				Name:  "firefox",
				Usage: "uninstall from the Firefox NSS security database",
			},
			cli.BoolFlag{
				Name:  "no-system",
				Usage: "disables the uninstall from the system's default trust store",
			},
			cli.BoolFlag{
				Name:  "all",
				Usage: "uninstall from Firefox's, Java's, and the system's default trust store",
			},
		},
	}
}

func installAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	cert, opts, err := getTruststoreOptions(ctx)
	if err != nil {
		return err
	}

	if err := truststore.Install(cert, opts...); err != nil {
		var truststoreErr *truststore.CmdError
		if errors.As(err, &truststoreErr) {
			return errors.Errorf("failed to execute \"%s\" failed with: %s",
				strings.Join(truststoreErr.Cmd().Args, " "), truststoreErr.Err())
		}
		return errors.Wrapf(err, "failed to install %s", filename)
	}

	fmt.Printf("Certificate %s has been installed.\n", filename)
	// Print certificate info (ignore errors)
	if s, err := certinfo.CertificateShortText(cert); err == nil {
		fmt.Print(s)
	}

	return nil
}

func uninstallAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	cert, opts, err := getTruststoreOptions(ctx)
	if err != nil {
		return err
	}

	if err := truststore.Uninstall(cert, opts...); err != nil {
		var truststoreErr *truststore.CmdError
		if errors.As(err, &truststoreErr) {
			return errors.Errorf("failed to execute \"%s\" failed with: %s",
				strings.Join(truststoreErr.Cmd().Args, " "), truststoreErr.Err())
		}
		return errors.Wrapf(err, "failed to uninstall %s", filename)
	}

	fmt.Printf("Certificate %s has been removed.\n", filename)
	// Print certificate info (ignore errors)
	if s, err := certinfo.CertificateShortText(cert); err == nil {
		fmt.Print(s)
	}

	return nil
}

func getTruststoreOptions(ctx *cli.Context) (*x509.Certificate, []truststore.Option, error) {
	cert, err := pemutil.ReadCertificate(ctx.Args().Get(0))
	if err != nil {
		return nil, nil, err
	}

	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, nil, errors.Errorf("certificate %s is not a root CA", ctx.Args().Get(0))
	}

	prefix := ctx.String("prefix")
	if prefix == "" {
		if cert.Subject.CommonName != "" {
			prefix = cert.Subject.CommonName + " "
		} else {
			prefix = "Smallstep Development CA "
		}
	}

	opts := []truststore.Option{
		truststore.WithPrefix(prefix),
	}

	if ctx.Bool("all") {
		opts = append(opts, truststore.WithJava(), truststore.WithFirefox())
	} else {
		if ctx.Bool("java") {
			opts = append(opts, truststore.WithJava())
		}
		if ctx.Bool("firefox") {
			opts = append(opts, truststore.WithFirefox())
		}
	}
	if ctx.Bool("no-system") {
		opts = append(opts, truststore.WithNoSystem())
	}
	return cert, opts, nil
}
