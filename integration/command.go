package integration

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/ThomasRooney/gexpect"
	"github.com/smallstep/assert"
)

// CleanOutput returns the output from the cursor character.
func CleanOutput(str string) string {
	if i := strings.Index(str, "?25h"); i > 0 {
		return str[i+4:]
	}
	return str
}

// Command executes a shell command.
func Command(command string) *exec.Cmd {
	return exec.Command("sh", "-c", command)
}

// ExitError converts an error to an exec.ExitError.
func ExitError(err error) (*exec.ExitError, bool) {
	v, ok := err.(*exec.ExitError)
	return v, ok
}

// Output executes a shell command and returns output from stdout.
func Output(command string) ([]byte, error) {
	return Command(command).Output()
}

// CombinedOutput executes a shell command and returns combined output from
// stdout and stderr.
func CombinedOutput(command string) ([]byte, error) {
	return Command(command).CombinedOutput()
}

// WithStdin executes a shell command with a provided reader used for stdin.
func WithStdin(command string, r io.Reader) ([]byte, error) {
	cmd := Command(command)
	cmd.Stdin = r
	return cmd.Output()
}

// CLICommand repreents a command-line command to execute.
type CLICommand struct {
	command   string
	arguments string
	flags     map[string]string
	stdin     io.Reader
}

// CLIOutput represents the output from executing a CLICommand.
// nolint:unused
type CLIOutput struct {
	stdout   string
	stderr   string
	combined string
}

// NewCLICommand generates a new CLICommand.
func NewCLICommand() CLICommand {
	return CLICommand{"", "", make(map[string]string), nil}
}

func (c CLICommand) setFlag(flag, value string) CLICommand {
	flags := make(map[string]string)
	for k, v := range c.flags {
		flags[k] = v
	}
	flags[flag] = value
	return CLICommand{c.command, c.arguments, flags, c.stdin}
}

func (c CLICommand) setCommand(command string) CLICommand {
	return CLICommand{command, c.arguments, c.flags, c.stdin}
}

func (c CLICommand) setArguments(arguments string) CLICommand {
	return CLICommand{c.command, arguments, c.flags, c.stdin}
}

func (c CLICommand) setStdin(stdin string) CLICommand {
	return CLICommand{c.command, c.arguments, c.flags, strings.NewReader(stdin)}
}

func (c CLICommand) cmd() string {
	flags := ""
	for key, value := range c.flags {
		if strings.Contains(value, " ") {
			value = "\"" + value + "\""
		}
		flags += fmt.Sprintf("--%s %s ", key, value)
	}
	return fmt.Sprintf("%s %s %s", c.command, c.arguments, flags)
}

func (c CLICommand) run() (CLIOutput, error) {
	var stdout, stderr, combined bytes.Buffer
	cmd := Command(c.cmd())
	cmd.Stdout = io.MultiWriter(&stdout, &combined)
	cmd.Stderr = io.MultiWriter(&stderr, &combined)
	cmd.Stdin = c.stdin
	err := cmd.Run()
	return CLIOutput{stdout.String(), stderr.String(), combined.String()}, err
}

func (c CLICommand) spawn() (*gexpect.ExpectSubprocess, error) {
	return gexpect.Spawn(c.cmd())
}

func (c CLICommand) test(t *testing.T, name string, expected string, msg ...interface{}) {
	t.Run(name, func(t *testing.T) {
		out, err := c.run()
		assert.FatalError(t, err, fmt.Sprintf("`%s`: returned error '%s'\n\nOutput:\n%s", c.cmd(), err, out.combined))
		assert.Equals(t, out.combined, expected, msg...)
	})
}

func (c CLICommand) fail(t *testing.T, name string, expected interface{}, msg ...interface{}) {
	t.Run(name, func(t *testing.T) {
		out, err := c.run()
		if assert.NotNil(t, err) {
			assert.Equals(t, err.Error(), "exit status 1")
		}
		switch v := expected.(type) {
		case string:
			assert.Equals(t, expected, out.stderr)
		case *regexp.Regexp:
			re := expected.(*regexp.Regexp)
			if !re.MatchString(out.stderr) {
				t.Errorf("Error message did not match regex:\n  Regex: %s\n\n  Output:\n%s", re.String(), out.stderr)
			}
		default:
			t.Errorf("unexpected type %T", v)
		}
		assert.Equals(t, "", out.stdout)
	})
}
