package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/step"
)

const (
	pluginPrefix = "step-"
	pluginSuffix = "-plugin"
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
			if _, err := os.Stat(path); err == nil { // #nosec G703 -- path to stat intentionally relies on (partial) user configuration
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

// Names returns the sorted, de-duplicated list of plugin names found on this
// system. A plugin is an executable named step-<name>-plugin located in the
// $(step path)/plugins directory or in one of the directories named by the PATH
// environment variable. The returned names are the <name> portion of the
// executable file name (without the step- prefix, the -plugin suffix, or, on
// Windows, the file extension).
func Names() []string {
	dirs := []string{filepath.Join(step.BasePath(), "plugins")}
	if path := os.Getenv("PATH"); path != "" {
		dirs = append(dirs, filepath.SplitList(path)...)
	}

	var exts []string
	if runtime.GOOS == "windows" {
		if x := os.Getenv(`PATHEXT`); x != "" {
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
	}

	var names []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Skip directories that don't exist or can't be read; a missing
			// plugins directory or PATH entry is not an error.
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := pluginName(entry.Name(), exts)
			if name == "" {
				continue
			}
			if slices.Contains(names, name) {
				continue
			}
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// pluginName extracts the plugin name from an executable file name, or returns
// the empty string if the file name doesn't match the step-<name>-plugin
// convention. On Windows the file extension (if listed in exts) is stripped
// before matching.
func pluginName(fileName string, exts []string) string {
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			fileName = fileName[:len(fileName)-len(ext)]
			break
		}
	}
	if !strings.HasPrefix(fileName, pluginPrefix) || !strings.HasSuffix(fileName, pluginSuffix) {
		return ""
	}
	return fileName[len(pluginPrefix) : len(fileName)-len(pluginSuffix)]
}

// Complete runs the plugin's shell completion and writes the candidate
// completions to the cli context's app writer. It execs the plugin binary with
// the arguments following the plugin name, plus the --generate-bash-completion
// flag, mirroring how the shell would invoke a native command for completion.
//
// This is needed because plugins are not registered cli commands, so urfave/cli
// never delegates completion to them on its own; instead it falls back to the
// app-level completion. Calling Complete from the app's BashComplete handler
// lets the plugin provide its own subcommand and flag completions.
func Complete(ctx *cli.Context, file string) error {
	// ctx.Args() holds the positional arguments with the shell-completion flag
	// already stripped, e.g. ["example", "hello"] for `step example hello
	// <TAB>`. Drop the plugin name itself and forward the rest to the plugin.
	tail := ctx.Args().Tail()
	args := make([]string, 0, len(tail)+1)
	args = append(args, tail...)
	args = append(args, "--generate-bash-completion")

	cmdName := file
	if runtime.GOOS == "windows" && strings.ToLower(filepath.Ext(file)) == ".ps1" {
		cmdName = "powershell"
		args = append([]string{"-noprofile", "-nologo", file}, args...)
	}

	cmd := exec.Command(cmdName, args...)
	cmd.Stdout = ctx.App.Writer
	// Discard the plugin's stderr: only stdout is consumed by the shell during
	// completion, and tools like cobra write noise (e.g. "Completion ended with
	// directive: ...") to stderr that would otherwise leak to the terminal.
	cmd.Stderr = nil
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
