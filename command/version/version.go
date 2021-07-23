package version

import (
	"fmt"

	"github.com/urfave/cli"

	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/step"
)

func init() {
	cmd := cli.Command{
		Name:        "version",
		Usage:       "display the current version of the cli",
		UsageText:   "**step version**",
		Description: `**step version** prints the version of the cli.`,
		Action:      Command,
	}

	command.Register(cmd)
}

// Command prints out the current version of the tool
func Command(c *cli.Context) error {
	fmt.Printf("%s\n", step.Version())
	fmt.Printf("Release Date: %s\n", step.ReleaseDate())
	return nil
}
