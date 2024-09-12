package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/step"
)

// LookPath searches for an executable named step-<name>-plugin in the $(step
// path)/plugins directory or in the directories named by the PATH environment
// variable. On Windows, files with the .com, .exe, .bat and .cmd extension
// will be checked to exist in the $(step path)/plugins directory first, after
// which the directories in the PATH environment variable will be inspected.
func LookPath(name string) (string, error) {
	fileName := "step-" + name + "-plugin"
	switch runtime.GOOS {
	case "windows":
		var exts []string
		x := os.Getenv(`PATHEXT`)
		if x != "" {
			for _, e := range strings.Split(strings.ToLower(x), `;`) {
				if e == "" {
					continue
				}
				if e[0] != '.' {
					e = "." + e
				}
				exts = append(exts, e)
			}
		} else {
			exts = []string{".com", ".exe", ".bat", ".cmd", ".ps1"}
		}
		for _, ext := range exts {
			path := filepath.Join(step.BasePath(), "plugins", fileName+ext)
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	default:
		path := filepath.Join(step.BasePath(), "plugins", fileName)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return exec.LookPath(fileName)
}

// Run starts the given command with the arguments in the context and waits for
// it to complete.
func Run(ctx *cli.Context, file string) error {
	args := ctx.Args()
	cmdName := file

	// if running on Windows and (likely) a PowerShell script, invoke powershell
	// with the arguments instead of the plugin file directly.
	if runtime.GOOS == "windows" && strings.ToLower(filepath.Ext(file)) == ".ps1" {
		cmdName = "powershell"
		args = append([]string{args[0], "-noprofile", "-nologo", file}, args[1:]...)
	}

	cmd := exec.Command(cmdName, args[1:]...)
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
