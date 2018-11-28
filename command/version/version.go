package version

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/config"
)

func init() {
	cmd := cli.Command{
		Name:   "version",
		Usage:  "display the current version of the cli",
		Action: Command,
	}

	command.Register(cmd)
}

// Command prints out the current version of the tool
func Command(c *cli.Context) error {
	fmt.Printf("%s\n", config.Version())
	fmt.Printf("Release Date: %s\n", config.ReleaseDate())
	return nil
}
