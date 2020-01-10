package certificate

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certinfo"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/truststore"
	"github.com/urfave/cli"
)

func installCommand() cli.Command {
	return cli.Command{
		Name:   "install",
		Action: command.ActionFunc(installAction),
		Usage:  "install a root certificate in the system truststore",
		UsageText: `**step certificate install** <crt-file>
		[**--prefix**=<name>] [**--all**]
		[**--java**] [**--firefox**] [**--no-system**]`,
		Description: `**step certificate install** installs a root certificate in the system
truststore.

Java and Firefox truststores are also supported via the respective flags.

## POSITIONAL ARGUMENTS

<crt-file>
:  Certificate to install in the system truststore

## EXAMPLES

Install a certificate in the system truststore:
'''
$ step certificate install root-ca.pem
'''

Install a certificate in all the supported truststores:
'''
$ step certificate install --all root-ca.pem
'''

Install a certificate in Firefox and the system trustore:
'''
$ step certificate install --firefox root--ca.pem
'''

Install a certificate in Java and the system trustore:
'''
$ step certificate install --java root-ca.pem
'''

Install a certificate in Firefox, Java, but not in the system trustore:
'''
$ step certificate install --firefox --java --no-system root-ca.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "prefix",
				Usage: `The prefix used to <name> the CA in the truststore. Defaults to the
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
				Usage: "disables the install on the system truststore",
			},
			cli.BoolFlag{
				Name:  "all",
				Usage: "install on the system, Firefox and Java truststores",
			},
		},
	}
}

func uninstallCommand() cli.Command {
	return cli.Command{
		Name:   "uninstall",
		Action: command.ActionFunc(uninstallAction),
		Usage:  "uninstall a root certificate from the system truststore",
		UsageText: `**step certificate uninstall** <crt-file>
		[**--prefix**=<name>] [**--all**]
		[**--java**] [**--firefox**] [**--no-system**]`,
		Description: `**step certificate install** uninstalls a root certificate from the system
truststore.

Java and Firefox truststores are also supported via the respective flags.

## POSITIONAL ARGUMENTS

<crt-file>
:  Certificate to uninstall from the system truststore

## EXAMPLES

Uninstall from only the system truststore:
'''
$ step certificate uninstall root-ca.pem
'''

Uninstall a certificate from all the supported truststores:
'''
$ step certificate uninstall --all root-ca.pem
'''

Uninstall a certificate from Firefox and the system trustore:
'''
$ step certificate uninstall --firefox root--ca.pem
'''

Uninstall a certificate infrom Java and the system trustore:
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
				Usage: `The prefix used to <name> the CA in the truststore. Defaults to the
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
				Usage: "disables the uninstall from the system truststore",
			},
			cli.BoolFlag{
				Name:  "all",
				Usage: "uninstall from the system, Firefox and Java truststores",
			},
		},
	}
}

func installAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	opts, err := getTruststoreOptions(ctx)
	if err != nil {
		return err
	}

	if err := truststore.InstallFile(filename, opts...); err != nil {
		switch err := err.(type) {
		case *truststore.CmdError:
			return errors.Errorf("failed to execute \"%s\" failed with: %s", strings.Join(err.Cmd().Args, " "), err.Err())
		default:
			return errors.Wrapf(err, "failed to install %s", filename)
		}
	}

	fmt.Printf("Certificate %s has been installed.\n", filename)
	// Print certificate info (ignore errors)
	if cert, err := pemutil.ReadCertificate(filename); err == nil {
		if s, err := certinfo.CertificateShortText(cert); err == nil {
			fmt.Print(s)
		}
	}

	return nil
}

func uninstallAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	opts, err := getTruststoreOptions(ctx)
	if err != nil {
		return err
	}

	if err := truststore.UninstallFile(filename, opts...); err != nil {
		switch err := err.(type) {
		case *truststore.CmdError:
			return errors.Errorf("failed to execute \"%s\" failed with: %s", strings.Join(err.Cmd().Args, " "), err.Err())
		default:
			return errors.Wrapf(err, "failed to uninstall %s", filename)
		}
	}

	fmt.Printf("Certificate %s has been removed.\n", filename)
	// Print certificate info (ignore errors)
	if cert, err := pemutil.ReadCertificate(filename); err == nil {
		if s, err := certinfo.CertificateShortText(cert); err == nil {
			fmt.Print(s)
		}
	}

	return nil
}

func getTruststoreOptions(ctx *cli.Context) ([]truststore.Option, error) {
	cert, err := pemutil.ReadCertificate(ctx.Args().Get(0))
	if err != nil {
		return nil, err
	}

	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.Errorf("certificate %s is not a root CA", ctx.Args().Get(0))
	}

	prefix := ctx.String("prefix")
	if prefix == "" {
		if len(cert.Subject.CommonName) > 0 {
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
	return opts, nil
}
