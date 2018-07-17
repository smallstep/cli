package flags

import (
	"fmt"
	"strings"

	"github.com/urfave/cli"
)

// OldPasswordFile returns a flag for receiving an old password
func OldPasswordFile(usage string) cli.Flag {
	if usage == "" {
		usage = "The path to the `FILE` containing the old encryption password"
	}

	return cli.StringFlag{
		Name:   "old-password-file, o",
		Usage:  usage,
		EnvVar: "STEP_OLD_PASSWORD_FILE",
	}
}

// NewPasswordFile returns a flag for receiving a new password
func NewPasswordFile(usage string) cli.Flag {
	if usage == "" {
		usage = "The path to the `FILE` containing the new encryption password"
	}

	return cli.StringFlag{
		Name:   "new-password-file, n",
		Usage:  usage,
		EnvVar: "STEP_NEW_PASSWORD_FILE",
	}
}

// Bits returns a flag for receiving the number of bits in generating a key
func Bits(usage string, value int) cli.Flag {
	if usage == "" {
		usage = "Number of bits used to generate the private key"
	}

	if value == 0 {
		value = 256
	}

	return cli.IntFlag{
		Name:   "bits, b",
		Usage:  usage,
		EnvVar: "STEP_BITS",
		Value:  value,
	}
}

// Action returns a flag for receiving an action out of several possibilities
func Action(usage string, possibilities []string, value string) cli.Flag {
	usage = fmt.Sprintf("%s (Options: %s)", usage, strings.Join(possibilities, ", "))
	return cli.StringFlag{
		Name:   "action, a",
		Usage:  usage,
		EnvVar: "STEP_ACTION",
		Value:  value,
	}
}

// Type returns a flag for receiving a type of thing to create out of several
// possibilties
func Type(usage string, possibilities []string, value string) cli.Flag {
	usage = fmt.Sprintf("%s (Options: %s)", usage, strings.Join(possibilities, ", "))
	return cli.StringFlag{
		Name:   "type, t",
		Usage:  usage,
		EnvVar: "STEP_TYPE",
		Value:  value,
	}
}

// Alg returns a flag for receiving the type of algorithm to use when performing an operation
func Alg(usage string, possibilities []string, value string) cli.Flag {
	usage = fmt.Sprintf("%s (Options: %s)", usage, strings.Join(possibilities, ", "))
	return cli.StringFlag{
		Name:   "alg",
		Usage:  usage,
		EnvVar: "STEP_ALG",
		Value:  value,
	}
}

// RootCertificate returns a flag for specifying the path to a root certificate
func RootCertificate(usage string) cli.Flag {
	if usage == "" {
		usage = "The file `PATH` to the root certificate"
	}

	return cli.StringFlag{
		Name:   "root, r",
		Usage:  usage,
		EnvVar: "STEP_ROOT_CERTIFICATE",
	}
}

// PasswordFile returns a flag for specifying the path to a file containing a password
func PasswordFile(usage string) cli.Flag {
	if usage == "" {
		usage = "Path to file containing a password"
	}

	return cli.StringFlag{
		Name:   "password-file, p",
		Usage:  usage,
		EnvVar: "STEP_PASSWORD_FILE",
	}
}

// OutputFile returns a flag for specifying the path inwhich to write output too
func OutputFile(usage string) cli.Flag {
	if usage == "" {
		usage = "Path to where the output should be written"
	}

	return cli.StringFlag{
		Name:   "output-file, o",
		Usage:  usage,
		EnvVar: "STEP_OUTPUT_FILE",
	}
}

// Number returns a flag for collecting the number of something to create
func Number(usage string) cli.Flag {
	if usage == "" {
		usage = "The `NUMBER` of entities to create"
	}

	return cli.StringFlag{
		Name:   "number, n",
		Usage:  usage,
		EnvVar: "STEP_NUMBER",
	}
}

// Prefix returns a flag for prefixing to the name of an entity during creation
func Prefix(usage, value string) cli.Flag {
	if usage == "" {
		usage = "The `PREFIX` to apply to the names of all created entities"
	}

	return cli.StringFlag{
		Name:   "prefix, p",
		Usage:  usage,
		Value:  value,
		EnvVar: "STEP_PREFIX",
	}
}

// OAuthProvider returns a flag for allowing the user to select an oauth provider
func OAuthProvider(usage string, providers []string, value string) cli.Flag {
	usage = fmt.Sprintf("%s (Options: %s)", usage, strings.Join(providers, ", "))
	return cli.StringFlag{
		Name:   "provider, idp",
		Usage:  usage,
		Value:  value,
		EnvVar: "STEP_PROVIDER",
	}
}

// Email returns a flag allowing the user to specify their email
func Email(usage string) cli.Flag {
	if usage == "" {
		usage = "Email to use"
	}

	return cli.StringFlag{
		Name:   "email, e",
		Usage:  usage,
		EnvVar: "STEP_EMAIL",
	}
}

// Console returns a flag allowing the user to specify whether or not they want
// to remain entirely in the console
func Console(usage string) cli.Flag {
	if usage == "" {
		usage = "Whether or not to remain entirely in the console to complete the action"
	}

	return cli.BoolFlag{
		Name:   "console, c",
		Usage:  usage,
		EnvVar: "STEP_CONSOLE",
	}
}

// Limit returns a flag for limiting the results return by a command
func Limit(usage string, value int) cli.Flag {
	if usage == "" {
		usage = "The maximum `NUMBER` of results to return"
	}
	if value == 0 {
		value = 10
	}

	return cli.IntFlag{
		Name:  "limit, l",
		Usage: usage,
		Value: value,
	}
}
