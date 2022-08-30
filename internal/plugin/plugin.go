package plugin

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/urfave/cli"
	"go.step.sm/cli-utils/step"
)

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
	//nolint:gosec // arguments controlled by step.
	cmd := exec.Command(file, args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// GetURL returns the project or the download URL of a well-known plugin.
func GetURL(name string) string {
	switch name {
	case "kms":
		return "https://github.com/smallstep/step-kms-plugin"
	default:
		return ""
	}
}
