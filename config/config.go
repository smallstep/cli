package config

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// version and buildTime are filled in during build by the Makefile
var (
	name      = "Smallstep CLI"
	buildTime = "N/A"
	commit    = "N/A"
)

// StepPathEnv defines the name of the environment variable that can overwrite
// the default configuration path.
const StepPathEnv = "STEPPATH"

// HomeEnv defines the name of the environment variable that can overwrite the
// default home directory.
const HomeEnv = "HOME"

// stepPath will be populated in init() with the proper STEPPATH.
var stepPath string

// homePath will be populated in init() with the proper HOME.
var homePath string

// StepPath returns the path for the step configuration directory, this is
// defined by the environment variable STEPPATH or if this is not set it will
// default to '$HOME/.step'.
func StepPath() string {
	return stepPath
}

// Home returns the user home directory using the environment variable HOME or
// the os/user package.
func Home() string {
	return homePath
}

// StepAbs returns the given path relative to the StepPath if it's not an
// absolute path or relative to the home directory using the special string
// "~/".
//
// Relative paths like 'certs/root_ca.crt' will be converted to
// '$STEPPATH/certs/root_ca.crt'. Home relative paths like ~/certs/root_ca.crt
// will be converted to '$HOME/certs/root_ca.crt'. And absolute paths like
// '/certs/root_ca.crt' will remain the same.
func StepAbs(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	// Windows accept both \ and /
	if slashed := filepath.ToSlash(path); strings.HasPrefix(slashed, "~/") {
		return filepath.Join(homePath, path[2:])
	}
	return filepath.Join(stepPath, path)
}

func init() {
	l := log.New(os.Stderr, "", 0)

	// Get home path from environment or from the user object.
	homePath = os.Getenv(HomeEnv)
	if homePath == "" {
		usr, err := user.Current()
		if err == nil && usr.HomeDir != "" {
			homePath = usr.HomeDir
		} else {
			l.Fatalf("Error obtaining home directory, please define environment variable %s.", HomeEnv)
		}
	}

	// Get step path from environment or relative to home.
	stepPath = os.Getenv(StepPathEnv)
	if stepPath == "" {
		stepPath = filepath.Join(homePath, ".step")
	}

	// Check for presence or attempt to create it if necessary.
	//
	// Some environments (e.g. third party docker images) might fail creating
	// the directory, so this should not panic if it can't.
	if fi, err := os.Stat(stepPath); err != nil {
		os.MkdirAll(stepPath, 0700)
	} else if !fi.IsDir() {
		l.Fatalf("File '%s' is not a directory.", stepPath)
	}
	// cleanup
	homePath = filepath.Clean(homePath)
	stepPath = filepath.Clean(stepPath)
}

// Set updates the Version and ReleaseDate
func Set(n, v, t string) {
	name = n
	buildTime = t
	commit = v
}

// Version returns the current version of the binary
func Version() string {
	out := commit
	if commit == "N/A" {
		out = "0000000-dev"
	}

	return fmt.Sprintf("%s/%s (%s/%s)",
		name, out, runtime.GOOS, runtime.GOARCH)
}

// ReleaseDate returns the time of when the binary was built
func ReleaseDate() string {
	out := buildTime
	if buildTime == "N/A" {
		out = time.Now().UTC().Format("2006-01-02 15:04 MST")
	}

	return out
}
