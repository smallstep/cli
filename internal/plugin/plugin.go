package plugin

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/urfave/cli"
	"go.step.sm/cli-utils/step"
)

// const kmsPlugin = "step-kms-plugin"

// LookPath searches for an executable named step-<name>-plugin in the $(step
// path)/plugins directory or in the directories named by the PATH environment
// variable.
func LookPath(name string) (string, error) {
	fileName := "step-" + name + "-plugin"
	path := filepath.Join(step.BasePath(), "plugins", fileName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return exec.LookPath(fileName)
}

// Run starts the given command with the arguments in the context and waits for
// it to complete.
func Run(ctx *cli.Context, file string) error {
	args := ctx.Args()
	cmd := exec.Command(file, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
