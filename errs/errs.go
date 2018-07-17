package errs

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

// err errExitCode is the default exit code when an error occurs.
const errExitCode = 1

// ErrTooFewArgs occurs when too few arguments were provided by the user
var ErrTooFewArgs = NewError("Not enough arguments were provided")

// ErrTooManyArgs occurs when too many arguments were provided by the user
var ErrTooManyArgs = NewError("Too many arguments were provided")

// ErrMissingArgs occurs when one or more arguments are missing
var ErrMissingArgs = NewError("An incorrect number of arguments were provided")

// ErrMissingToken occurs when a STEP_TOKEN or --token flag is not provided
var ErrMissingToken = NewError("A one-time token must be provided to bootstrap the identity via the `--token` flag or `$STEP_TOKEN` environment variable")

// ErrMissingCAURL occurs when a STEP_CA_URL or --ca-url flag is not provided
var ErrMissingCAURL = NewError("The CA URL must be provided through the --ca-url flag or `$STEP_CA_URL` environment variable")

// NewError returns a new Error for the given format and arguments
func NewError(format string, args ...interface{}) error {
	return errors.Errorf(format, args...)
}

// NewExitError returns an error than the urfave/cli package will handle and
// will show the given error and exit with the given code.
func NewExitError(err error, exitCode int) error {
	return cli.NewExitError(err, exitCode)
}

// Wrap returns a new error wrapped by the given error with the given message.
// If the given error implements the errors.Cause interface, the base error is
// used. If the given error is wrapped by a package name, the error wrapped
// will be the string after the last colon.
func Wrap(err error, format string, args ...interface{}) error {
	cause := errors.Cause(err)
	if cause == err {
		str := err.Error()
		if i := strings.LastIndexByte(str, ':'); i >= 0 {
			str = strings.TrimSpace(str[i:])
			return errors.Wrapf(fmt.Errorf(str), format, args...)
		}
	}
	return errors.Wrapf(cause, format, args...)
}

// UsageExitError prints out the usage error followed by the help documentation
// for the command
func UsageExitError(c *cli.Context, err error) error {
	msg := fmt.Sprintf("Error: %s\n\n%s", err.Error(), usageString(c))
	return cli.NewExitError(msg, errExitCode)
}

// UnexpectedExitError wraps the error denoting that it was unexpected
func UnexpectedExitError(err error) error {
	msg := fmt.Sprintf("Error: An unexpected error was encountered: %s", err.Error())
	return cli.NewExitError(msg, errExitCode)
}

// ToError transforms the given error into our frameworks error type
func ToError(err error) error {
	switch err.(type) {
	case nil:
		return nil
	default:
		return cli.NewExitError(prependErrorMsg(err), errExitCode)
	}
}

func prependErrorMsg(err error) string {
	m := err.Error()
	if strings.HasPrefix(m, "Error:") {
		return m
	}

	return "Error: " + m
}

// InsecureCommand returns an error with a message saying that the current
// command requires the insecure flag.
func InsecureCommand(ctx *cli.Context) error {
	return errors.Errorf("'%s %s' requires the '--insecure' flag", ctx.App.Name, ctx.Command.Name)
}

// EqualArguments returns an error saying that the given positional arguments
// cannot be equal.
func EqualArguments(ctx *cli.Context, arg1, arg2 string) error {
	return errors.Errorf("positional arguments <%s> and <%s> cannot be equal in '%s'", arg1, arg2, usage(ctx))
}

// MissingArguments returns an error with a missing arguments message for the
// given positional argument names.
func MissingArguments(ctx *cli.Context, argNames ...string) error {
	switch len(argNames) {
	case 0:
		return errors.Errorf("missing positional arguments in '%s'", usage(ctx))
	case 1:
		return errors.Errorf("missing positional argument <%s> in '%s'", argNames[0], usage(ctx))
	default:
		args := make([]string, len(argNames))
		for i, name := range argNames {
			args[i] = "<" + name + ">"
		}
		return errors.Errorf("missing positional argument %s in '%s'", strings.Join(args, " "), usage(ctx))
	}
}

// NumberOfArguments returns nil if the number of positional arguments is
// equal to the required one. It will return an appropriate error if they are
// not.
func NumberOfArguments(ctx *cli.Context, required int) error {
	n := ctx.NArg()
	switch {
	case n < required:
		return TooFewArguments(ctx)
	case n > required:
		return TooManyArguments(ctx)
	default:
		return nil
	}
}

// TooFewArguments returns an error with a few arguments were provided message.
func TooFewArguments(ctx *cli.Context) error {
	return errors.Errorf("not enough positional arguments were provided in '%s'", usage(ctx))
}

// TooManyArguments returns an error with a too many arguments were provided
// message.
func TooManyArguments(ctx *cli.Context) error {
	return errors.Errorf("too many positional arguments were provided in '%s'", usage(ctx))
}

// InsecureArgument returns an error with the given argument requiring the
// --insecure flag.
func InsecureArgument(ctx *cli.Context, name string) error {
	return errors.Errorf("positional argument <%s> requires the '--insecure' flag", name)
}

// FlagValueInsecure returns an error with the given flag and value requiring
// the --insecure flag.
func FlagValueInsecure(ctx *cli.Context, flag string, value string) error {
	return errors.Errorf("flag '--%s %s' requires the '--insecure' flag", flag, value)
}

// InvalidFlagValue returns an error with the given value being missing or
// invalid for the given flag. Optionally it lists the given formated options
// at the end.
func InvalidFlagValue(ctx *cli.Context, flag string, value string, options string) error {
	var format string
	if len(value) == 0 {
		format = fmt.Sprintf("missing value for flag '--%s'", flag)
	} else {
		format = fmt.Sprintf("invalid value '%s' for flag '--%s'", value, flag)
	}

	if len(options) == 0 {
		return errors.New(format)
	}

	return errors.New(format + " options are " + options)
}

// IncompatibleFlag returns an error with the flag being incompatible with the
// given value.
func IncompatibleFlag(ctx *cli.Context, flag string, value string) error {
	return errors.Errorf("flag '--%s' is incompatible with '%s'", flag, value)
}

// RequiredFlag returns an error with the required flag message.
func RequiredFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("'%s %s' requires the '--%s' flag", ctx.App.HelpName,
		ctx.Command.Name, flag)
}

// RequiredWithFlag returns an error with the required flag message with another flag.
func RequiredWithFlag(ctx *cli.Context, required, with string) error {
	return errors.Errorf("flag '--%s' requires the '--%s' flag", required, with)
}

// RequiredInsecureFlag returns an error with the required flag message unless
// the insecure flag is used.
func RequiredInsecureFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("flag '--%s' requires the '--insecure' flag", flag)
}

// RequiredSubtleFlag returns an error with the required flag message unless
// the subtle flag is used.
func RequiredSubtleFlag(ctx *cli.Context, flag string) error {
	return errors.Errorf("flag '--%s' requires the --subtle' flag", flag)
}

// RequiredOrFlag returns an error with a list of flags being required messages.
func RequiredOrFlag(ctx *cli.Context, flags ...string) error {
	params := make([]string, len(flags))
	for i, flag := range flags {
		params[i] = "--" + flag
	}
	return errors.Errorf("flag %s are required", strings.Join(params, " or "))
}

// MinSizeFlag returns an error with a greater or equal message message for
// the given flag and size.
func MinSizeFlag(ctx *cli.Context, flag string, size string) error {
	return errors.Errorf("flag '--%s' must be greater or equal than %s", flag, size)
}

// MinSizeInsecureFlag returns an error with a requiring --insecure flag
// message with the given flag an size.
func MinSizeInsecureFlag(ctx *cli.Context, flag, size string) error {
	return errors.Errorf("flag '--%s' requires at least %s unless '--insecure' flag is provided", flag, size)
}

// MutuallyExclusiveFlags returns an error with mutually exclusive message for
// the given flags.
func MutuallyExclusiveFlags(ctx *cli.Context, flag1, flag2 string) error {
	return errors.Errorf("flag '--%s' and flag '--%s' are mutually exclusive", flag1, flag2)
}

// usage returns the command usage text if set or a default usage string.
func usage(ctx *cli.Context) string {
	if len(ctx.Command.UsageText) == 0 {
		return fmt.Sprintf("%s %s [command options]", ctx.App.HelpName, ctx.Command.Name)
	}

	return ctx.Command.UsageText
}

// usageString returns the command usage prepended by the string "Usage: ".
func usageString(ctx *cli.Context) string {
	return "Usage: " + usage(ctx)
}

// FileError is a wrapper for errors of the os package.
func FileError(err error, filename string) error {
	switch e := errors.Cause(err).(type) {
	case *os.PathError:
		return errors.Errorf("%s %s failed: %v", e.Op, e.Path, e.Err)
	case *os.LinkError:
		return errors.Errorf("%s %s %s failed %v:", e.Op, e.Old, e.New, e.Err)
	case *os.SyscallError:
		return errors.Errorf("%s failed %v:", e.Syscall, e.Err)
	default:
		return Wrap(err, "unexpected error on %s", filename)
	}
}
