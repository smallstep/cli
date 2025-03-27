package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/step"
	"github.com/smallstep/cli-utils/ui"
	"github.com/smallstep/cli-utils/usage"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/command/version"
	"github.com/smallstep/cli/internal/plugin"
	"github.com/smallstep/cli/utils"

	// Enabled cas interfaces.
	_ "github.com/smallstep/certificates/cas/cloudcas"
	_ "github.com/smallstep/certificates/cas/softcas"
	_ "github.com/smallstep/certificates/cas/stepcas"

	// Enabled commands
	_ "github.com/smallstep/cli/command/api"
	_ "github.com/smallstep/cli/command/base64"
	_ "github.com/smallstep/cli/command/beta"
	_ "github.com/smallstep/cli/command/ca"
	_ "github.com/smallstep/cli/command/certificate"
	_ "github.com/smallstep/cli/command/completion"
	_ "github.com/smallstep/cli/command/context"
	_ "github.com/smallstep/cli/command/crl"
	_ "github.com/smallstep/cli/command/crypto"
	_ "github.com/smallstep/cli/command/fileserver"
	_ "github.com/smallstep/cli/command/oauth"
	_ "github.com/smallstep/cli/command/path"
	_ "github.com/smallstep/cli/command/ssh"
)

// Version is set by an LDFLAG at build time representing the git tag or commit
// for the current release
var Version = "N/A"

// BuildTime is set by an LDFLAG at build time representing the timestamp at
// the time of build
var BuildTime = "N/A"

func init() {
	step.Set("Smallstep CLI", Version, BuildTime)
	ca.UserAgent = step.Version()
}

func main() {
	// initialize step environment.
	if err := step.Init(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	defer panicHandler()

	// create new instance of app
	app := newApp(os.Stdout, os.Stderr)

	if err := app.Run(os.Args); err != nil {
		var messenger interface {
			Message() string
		}
		if errors.As(err, &messenger) {
			if os.Getenv("STEPDEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "%+v\n\n%s", err, messenger.Message())
			} else {
				fmt.Fprintln(os.Stderr, messenger.Message())
				fmt.Fprintln(os.Stderr, "Re-run with STEPDEBUG=1 for more info.")
			}
		} else {
			if os.Getenv("STEPDEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, err)
			}
		}
		//nolint:gocritic // ignore exitAfterDefer error because the defer is required for recovery.
		os.Exit(1)
	}
}

func newApp(stdout, stderr io.Writer) *cli.App {
	// Define default file writers and prompters for go.step.sm/crypto
	pemutil.WriteFile = utils.WriteFile
	pemutil.PromptPassword = func(msg string) ([]byte, error) {
		return ui.PromptPassword(msg)
	}
	jose.PromptPassword = func(msg string) ([]byte, error) {
		return ui.PromptPassword(msg)
	}

	// Override global framework components
	cli.VersionPrinter = func(c *cli.Context) {
		version.Command(c)
	}
	cli.AppHelpTemplate = usage.AppHelpTemplate
	cli.SubcommandHelpTemplate = usage.SubcommandHelpTemplate
	cli.CommandHelpTemplate = usage.CommandHelpTemplate
	cli.HelpPrinter = usage.HelpPrinter
	cli.FlagNamePrefixer = usage.FlagNamePrefixer
	cli.FlagStringer = stringifyFlag

	// Configure cli app
	app := cli.NewApp()
	app.Name = "step"
	app.HelpName = "step"
	app.Usage = "plumbing for distributed systems"
	app.Version = step.Version()
	app.Commands = command.Retrieve()
	app.Flags = append(app.Flags, cli.HelpFlag)
	app.EnableBashCompletion = true
	app.Copyright = fmt.Sprintf("(c) 2018-%d Smallstep Labs, Inc.", time.Now().Year())

	// Flag of custom configuration flag
	app.Flags = append(app.Flags, cli.StringFlag{
		Name:  "config",
		Usage: "path to the config file to use for CLI flags",
	})

	// Action runs on `step` or `step <command>` if the command is not enabled.
	app.Action = func(ctx *cli.Context) error {
		args := ctx.Args()
		if name := args.First(); name != "" {
			if file, err := plugin.LookPath(name); err == nil {
				return plugin.Run(ctx, file)
			}
			if u := plugin.GetURL(name); u != "" {
				//nolint:stylecheck // this is a top level error - capitalization is ok
				return fmt.Errorf("The plugin %q was not found on this system.\nDownload it from %s", name, u)
			}
			return cli.ShowCommandHelp(ctx, name)
		}
		return cli.ShowAppHelp(ctx)
	}

	// All non-successful output should be written to stderr
	app.Writer = stdout
	app.ErrWriter = stderr

	return app
}

func panicHandler() {
	if r := recover(); r != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%s\n", step.Version())
			fmt.Fprintf(os.Stderr, "Release Date: %s\n\n", step.ReleaseDate())
			panic(r)
		}

		fmt.Fprintln(os.Stderr, "Something unexpected happened.")
		fmt.Fprintln(os.Stderr, "If you want to help us debug the problem, please run:")
		fmt.Fprintf(os.Stderr, "STEPDEBUG=1 %s\n", strings.Join(os.Args, " "))
		fmt.Fprintln(os.Stderr, "and send the output to info@smallstep.com")
		os.Exit(2)
	}
}

func flagValue(f cli.Flag) reflect.Value {
	fv := reflect.ValueOf(f)
	for fv.Kind() == reflect.Ptr {
		fv = reflect.Indirect(fv)
	}
	return fv
}

var placeholderString = regexp.MustCompile(`<.*?>`)

func stringifyFlag(f cli.Flag) string {
	fv := flagValue(f)
	usg := fv.FieldByName("Usage").String()
	placeholder := placeholderString.FindString(usg)
	if placeholder == "" {
		switch f.(type) {
		case cli.BoolFlag, cli.BoolTFlag:
		default:
			placeholder = "<value>"
		}
	}
	return cli.FlagNamePrefixer(fv.FieldByName("Name").String(), placeholder) + "\t" + usg
}
