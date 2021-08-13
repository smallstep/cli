package ssh

import (
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"
)

func configCommand() cli.Command {
	return cli.Command{
		Name:   "config",
		Action: command.ActionFunc(configAction),
		Usage:  "configures ssh to be used with certificates",
		UsageText: `**step ssh config**
[**--team**=<name>] [**--host**] [**--set**=<key=value>] [**--set-file**=<file>]
[**--dry-run**] [**--roots**] [**--federation**] [**--force**]
[**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<context]
[**--context-name**=<string>] [**--context-profile**=<string>]`,
		Description: `**step ssh config** configures SSH to be used with certificates. It also supports
flags to inspect the root certificates used to sign the certificates.

This command uses the templates defined in step-certificates to set up user and
hosts environments.

## EXAMPLES

Print the public keys used to verify user certificates:
'''
$ step ssh config --roots
'''

Print the public keys used to verify host certificates:
'''
$ step ssh config --host --roots
'''

Apply configuration templates on the user system:
'''
$ step ssh config
'''

Apply configuration templates on a host:
'''
$ step ssh config --host
'''

Apply configuration templates with custom variables:
'''
$ step ssh config --set User=joe --set Bastion=bastion.example.com
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "host",
				Usage: `Configures a SSH server instead of a client.`,
			},
			flags.Team,
			flags.TeamURL,
			cli.BoolFlag{
				Name:  "roots",
				Usage: `Prints the public keys used to verify user or host certificates.`,
			},
			cli.BoolFlag{
				Name: "federation",
				Usage: `Prints all the public keys in the federation. These keys are used to verify
user or host certificates`,
			},
			cli.StringSliceFlag{
				Name: "set",
				Usage: `The <key=value> used as a variable in the templates. Use the flag multiple
times to set multiple variables.`,
			},
			flags.TemplateSetFile,
			flags.DryRun,
			flags.Force,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.Context,
			flags.ContextName,
			flags.ContextProfile,
		},
	}
}

type statusCoder interface {
	StatusCode() int
}

func configAction(ctx *cli.Context) (recoverErr error) {
	team := ctx.String("team")
	isHost := ctx.Bool("host")
	isRoots := ctx.Bool("roots")
	isFederation := ctx.Bool("federation")
	sets := ctx.StringSlice("set")

	context := ctx.String("context")
	contextName := ctx.String("context-name")
	contextProfile := ctx.String("context-profile")

	switch {
	case team != "" && isHost:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "host")
	case team != "" && isRoots:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "isRoots")
	case team != "" && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "federation")
	case team != "" && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "set")
	case team != "" && context != "":
		return errs.IncompatibleFlagWithFlag(ctx, "team", "context")
	case isRoots && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "federation")
	case isRoots && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "set")
	case isFederation && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "federation", "set")
	case context != "" && contextName != "":
		return errs.IncompatibleFlagWithFlag(ctx, "context", "context-name")
	case context != "" && contextProfile != "":
		return errs.IncompatibleFlagWithFlag(ctx, "context", "context-profile")
	}

	// Bootstrap Authority
	if team != "" {
		if err := cautils.BootstrapTeamAuthority(ctx, team, "ssh"); err != nil {
			return err
		}
	}

	args := []string{"ssh", "config-helper"}
	args = append(args, os.Args[3:]...)

	if step.IsContextEnabled() {
		switch {
		case context != "":
			args = append(args, "--context", context)
		case team != "" && contextName != "":
			args = append(args, "--context", contextName)
		case team != "":
			args = append(args, "--context", "ssh."+team)
		}
	}

	if _, err := exec.Step(args...); err != nil {
		return errors.Wrap(err, "error configuring ssh")
	}
	return nil
}
