package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command/version"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/usage"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/step"

	// Enabled commands
	_ "github.com/smallstep/cli/command/base64"
	_ "github.com/smallstep/cli/command/beta"
	_ "github.com/smallstep/cli/command/ca"
	_ "github.com/smallstep/cli/command/certificate"
	_ "github.com/smallstep/cli/command/context"
	_ "github.com/smallstep/cli/command/crypto"
	_ "github.com/smallstep/cli/command/fileserver"
	_ "github.com/smallstep/cli/command/oauth"
	_ "github.com/smallstep/cli/command/path"
	_ "github.com/smallstep/cli/command/ssh"

	// Enabled cas interfaces.
	_ "github.com/smallstep/certificates/cas/cloudcas"
	_ "github.com/smallstep/certificates/cas/softcas"
	_ "github.com/smallstep/certificates/cas/stepcas"

	// Profiling and debugging
	_ "net/http/pprof"
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
	rand.Seed(time.Now().UnixNano())
}

func main() {
	defer panicHandler()
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
	app.Copyright = "(c) 2018-2020 Smallstep Labs, Inc."

	// Flag of custom configuration flag
	app.Flags = append(app.Flags, cli.StringFlag{
		Name:  "config",
		Usage: "path to the config file to use for CLI flags",
	})

	// All non-successful output should be written to stderr
	app.Writer = os.Stdout
	app.ErrWriter = os.Stderr

	// Start the golang debug logger if environment variable is set.
	// See https://golang.org/pkg/net/http/pprof/
	debugProfAddr := os.Getenv("STEP_PROF_ADDR")
	if debugProfAddr != "" {
		go func() {
			log.Println(http.ListenAndServe(debugProfAddr, nil))
		}()
	}

	if err := app.Run(os.Args); err != nil {
		if fe, ok := err.(errs.FriendlyError); ok {
			if os.Getenv("STEPDEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "%+v\n\n%s", err, fe.Message())
			} else {
				fmt.Fprintln(os.Stderr, fe.Message())
				fmt.Fprintln(os.Stderr, "Re-run with STEPDEBUG=1 for more info.")
			}
		} else {
			if os.Getenv("STEPDEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, err)
			}
		}
		// ignore exitAfterDefer error because the defer is required for recovery.
		// nolint:gocritic
		os.Exit(1)
	}
}

func panicHandler() {
	if r := recover(); r != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%s\n", step.Version())
			fmt.Fprintf(os.Stderr, "Release Date: %s\n\n", step.ReleaseDate())
			panic(r)
		} else {
			fmt.Fprintln(os.Stderr, "Something unexpected happened.")
			fmt.Fprintln(os.Stderr, "If you want to help us debug the problem, please run:")
			fmt.Fprintf(os.Stderr, "STEPDEBUG=1 %s\n", strings.Join(os.Args, " "))
			fmt.Fprintln(os.Stderr, "and send the output to info@smallstep.com")
			os.Exit(2)
		}
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
