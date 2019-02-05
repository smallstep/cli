package certificate

import (
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/truststore"
	"github.com/urfave/cli"
)

func installCommand() cli.Command {
	return cli.Command{
		Name:   "install",
		Action: command.ActionFunc(installAction),
		Usage:  "install certificate in the system truststore",
		UsageText: `**step certificate install** <crt-file>
		[**--prefix**=<name>] [**--uninstall**]
		[**--java**] [**--firefox**] [**--all**]`,
		Description: `**step certificate install** install certificate in the system truststore.

Java and Firefox truststores are also supported if the properly flags are
passed.

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
$ step certificate install -all root-ca.pem
'''

Uninstall a certificate from all the supported trustores:
'''
$ step certificate install -uninstall -all root-ca.pem
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "prefix",
				Usage: "prefix used to name the CA in the truststore",
				Value: "Smallstep Development CA ",
			},
			cli.BoolFlag{
				Name:  "uninstall",
				Usage: "uninstall the given certificate",
			},
			cli.BoolFlag{
				Name:  "java",
				Usage: "install or uninstall on the Java key store",
			},
			cli.BoolFlag{
				Name:  "firefox",
				Usage: "install or uninstall on the Firefox NSS security database",
			},
			cli.BoolFlag{
				Name:  "no-system",
				Usage: "disables the install or uninstall on the system truststore",
			},
			cli.BoolFlag{
				Name:  "all",
				Usage: "install or uninstall on the system, Firefox and Java truststores",
			},
		},
	}
}

func installAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	opts := []truststore.Option{
		truststore.WithPrefix(ctx.String("prefix")),
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

	if ctx.Bool("uninstall") {
		if err := truststore.UninstallFile(filename, opts...); err != nil {
			return err
		}

		ui.Printf("Certificate %s has been properly removed.", filename)
		return nil
	}

	if err := truststore.InstallFile(filename, opts...); err != nil {
		return err
	}

	ui.Printf("Certificate %s has been properly installed.", filename)
	return nil
}
