package command

import (
	"github.com/smallstep/cli/usage"
	"github.com/urfave/cli"
)

var cmds []cli.Command

func init() {
	cmds = []cli.Command{
		usage.HelpCommand(),
	}
}

// Register adds the given command to the global list of commands
func Register(c cli.Command) {
	cmds = append(cmds, c)
}

// Retrieve returns all commands
func Retrieve() []cli.Command {
	return cmds
}
