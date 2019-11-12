package exec

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

// LookPath is an alias for exec.LookPath. It searches for an executable named
// file in the directories named by the PATH environment variable. If file
// contains a slash, it is tried directly and the PATH is not consulted. The
// result may be an absolute path or a path relative to the current directory.
func LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// IsWSL returns true if Windows Subsystem for Linux is detected.
//
// "Official" way of detecting WSL
// https://github.com/Microsoft/WSL/issues/423#issuecomment-221627364
func IsWSL() bool {
	b, err := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "Microsoft") || strings.Contains(string(b), "WSL")
}

// Exec is wrapper over syscall.Exec, invokes the execve(2) system call. On
// windows it executes Run with the same arguments.
func Exec(name string, arg ...string) {
	if runtime.GOOS == "windows" {
		Run(name, arg...)
		return
	}
	args := append([]string{name}, arg...)
	if err := syscall.Exec(name, args, os.Environ()); err != nil {
		errorAndExit(name, err)
	}
}

// Run is a wrapper over os/exec Cmd.Run that configures Stderr/Stdin/Stdout
// to the current ones and wait until the process finishes, exiting with the
// same code. Run will also forward all the signals sent to step to the
// command.
func Run(name string, arg ...string) {
	cmd, exitCh, err := run(name, arg...)
	if err != nil {
		errorAndExit(name, err)
	}

	if err = cmd.Wait(); err != nil {
		errorf(name, err)
	}

	// exit and wait until os.Exit
	exitCh <- getExitStatus(cmd)
	exitCh <- 0
}

// RunWithPid calls Run and writes the process ID in pidFile.
func RunWithPid(pidFile, name string, arg ...string) {
	f, err := os.OpenFile(pidFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		errorAndExit(name, err)
	}

	// Run process
	cmd, exitCh, err := run(name, arg...)
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		errorAndExit(name, err)
	}

	// Write pid
	f.Write([]byte(strconv.Itoa(cmd.Process.Pid)))
	f.Close()

	// Wait until it finishes
	if err = cmd.Wait(); err != nil {
		errorf(name, err)
	}

	// clean, exit and wait until os.Exit
	os.Remove(f.Name())
	exitCh <- getExitStatus(cmd)
	exitCh <- 0
}

// OpenInBrowser opens the given url on a web browser
func OpenInBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		if IsWSL() {
			cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
		} else {
			cmd = exec.Command("xdg-open", url)
		}
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return errors.Errorf("unsupported platform '%s'", runtime.GOOS)
	}

	return errors.WithStack(cmd.Start())
}

// Step executes step with the given commands and returns the standard output.
func Step(args ...string) ([]byte, error) {
	var stdout bytes.Buffer
	cmd := exec.Command(os.Args[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdout

	if err := cmd.Start(); nil != err {
		return nil, errors.Wrapf(err, "error starting: %s %s", os.Args[0], strings.Join(args, " "))
	}
	if err := cmd.Wait(); nil != err {
		return nil, errors.Wrapf(err, "error running: %s %s", os.Args[0], strings.Join(args, " "))
	}

	return stdout.Bytes(), nil
}

// Command executes the given command with it's arguments and returns the
// standard output.
func Command(name string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "error running %s %s:\n%s", name, strings.Join(args, " "), stderr.String())
	}
	return out, nil
}

func run(name string, arg ...string) (*exec.Cmd, chan int, error) {
	cmd := exec.Command(name, arg...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	// Start process
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	// Forward signals
	exitCh := make(chan int)
	go signalHandler(cmd, exitCh)

	return cmd, exitCh, nil
}

func getExitStatus(cmd *exec.Cmd) int {
	if cmd.ProcessState != nil {
		switch sys := cmd.ProcessState.Sys().(type) {
		case syscall.WaitStatus:
			return sys.ExitStatus()
		}
	}
	return 1
}

func errorf(name string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", path.Base(name), err.Error())
}

func errorAndExit(name string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", path.Base(name), err.Error())
	os.Exit(-1)
}

// signalHandler forwards all the signals to the cmd.
func signalHandler(cmd *exec.Cmd, exitCh chan int) {
	// signal.Notify prefers a buffered channel. From documentation: "For a
	// channel used for notification of just one signal value, a buffer of size
	// 1 is sufficient." As we do not know how many signal values the cmd is
	// expecting we select 1 as a sane default. In the future maybe we can make
	// this value configurable.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals)
	defer signal.Stop(signals)
	for {
		select {
		case sig := <-signals:
			cmd.Process.Signal(sig)
		case code := <-exitCh:
			os.Exit(code)
		}
	}
}
