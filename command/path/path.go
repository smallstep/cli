package path

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/step"
)

func init() {
	cmd := cli.Command{
		Name:      "path",
		Usage:     "print the configured step path and exit",
		UsageText: "**step path** [**--base**] [**--profile**]",
		Description: `**step path** command prints the configured step path and exits.

When using contexts to manage 'step-ca' environments, this command will return
the current authority path. If no current context is configured this command the
default step path of $HOME/.step, which can be overridden with the **STEPPATH**
environment variable.

## EXAMPLES

Get the path with no current context configured:
'''
$ step path
/Users/max/.step
'''

Get the path with no current context and environment variable STEPPATH overriding the default:
'''
$ export STEPPATH=/tmp/step
$ step path
/tmp/step
'''

Get the path with a current context (configured at $STEPPATH/current-context.json):
'''
$ cat $(step path --base)/current-context.json
{"context": "machine.step-internal.net"}

$ step path
/Users/max/.step/authorities/machine.step-internal.net
'''

Get the base path:
'''
$ step path --base
/Users/max/.step
'''

Get the base path with environment variable STEPPATH overriding the default:
'''
$ export STEPPATH=/tmp/step
$ step path --base
/tmp/step
'''

Get the path of the current profile:
'''
$ cat $(step path --base)/current-context.json
{"context": "ca.acme.net"}

$ cat $(step path --base)/contexts.json
{
	"ca.beta.net": {
        "profile": "beta-corp",
        "authority": "machine.beta.net"
    },
	"ca.acme.net": {
        "profile": "example-corp",
        "authority": "machine.acme.net"
    }

}
$ step path --profile
/Users/max/.step/profiles/beta-corp
'''
`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "base",
				Usage: "Return the base of the step path",
			},
			cli.BoolFlag{
				Name:  "profile",
				Usage: "Return the base path of the currently configured default profile",
			},
		},
		Action: cli.ActionFunc(func(ctx *cli.Context) error {
			if ctx.Bool("base") {
				fmt.Println(step.BasePath())
				return nil
			}
			if ctx.Bool("profile") {
				fmt.Println(step.ProfilePath())
				return nil
			}
			fmt.Println(step.Path())
			return nil
		}),
	}

	command.Register(cmd)
}
