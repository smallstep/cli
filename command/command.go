package command

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/usage"
	"github.com/urfave/cli"
)

var cmds []cli.Command

func init() {
	cmds = []cli.Command{
		usage.HelpCommand(),
	}
}

// Register adds the given command to the global list of commands.
// It sets recursively the command Flags environment variables.
func Register(c cli.Command) {
	setEnvVar(&c)
	cmds = append(cmds, c)
}

// Retrieve returns all commands
func Retrieve() []cli.Command {
	return cmds
}

// getConfigVars load the defaults.json file and sets the flags if they are not
// already set.
//
// TODO(mariano): right now it only supports parameters at first level.
func getConfigVars(ctx *cli.Context) error {
	configFile := ctx.GlobalString("config")
	if configFile == "" {
		configFile = filepath.Join(config.StepPath(), "config", "defaults.json")
	}

	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil
	}

	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		return errors.Wrapf(err, "error parsing %s", configFile)
	}

	for _, name := range ctx.FlagNames() {
		if ctx.IsSet(name) {
			continue
		}
		if v, ok := m[name]; ok {
			ctx.Set(name, fmt.Sprintf("%v", v))
		}
	}

	return nil
}

// getEnvVar generates the environment variable for the given flag name.
func getEnvVar(name string) string {
	parts := strings.Split(name, ",")
	name = strings.TrimSpace(parts[0])
	name = strings.Replace(name, "-", "_", -1)
	return "STEP_" + strings.ToUpper(name)
}

// setEnvVar sets the the EnvVar element to each flag recursively.
func setEnvVar(c *cli.Command) {
	if c == nil {
		return
	}

	// Enable getting the flags from a json file
	if c.Before == nil && c.Action != nil {
		c.Before = getConfigVars
	}

	// Enable getting the flags from environment variables
	for i := range c.Flags {
		envVar := getEnvVar(c.Flags[i].GetName())
		switch f := c.Flags[i].(type) {
		case cli.BoolFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.BoolTFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.DurationFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.Float64Flag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.GenericFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.Int64Flag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.IntFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.IntSliceFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.Int64SliceFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.StringFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.StringSliceFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.Uint64Flag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		case cli.UintFlag:
			if f.EnvVar == "" {
				f.EnvVar = envVar
				c.Flags[i] = f
			}
		}
	}

	for i := range c.Subcommands {
		setEnvVar(&c.Subcommands[i])
	}
}
