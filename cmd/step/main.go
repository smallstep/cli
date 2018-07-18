package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/command/version"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/usage"

	// Enabled commands
	_ "github.com/smallstep/cli/command/certificate"
	_ "github.com/smallstep/cli/command/crypto"
	_ "github.com/smallstep/cli/command/oauth"

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
	config.Set(Version, BuildTime)
}

func main() {
	// Override global framework components
	cli.VersionPrinter = func(c *cli.Context) {
		version.Command(c)
	}
	cli.AppHelpTemplate = usage.AppHelpTemplate
	cli.SubcommandHelpTemplate = usage.SubcommandHelpTemplate
	cli.CommandHelpTemplate = usage.CommandHelpTemplate
	cli.HelpPrinter = helpPrinter
	cli.FlagNamePrefixer = usage.FlagNamePrefixer
	cli.FlagStringer = stringifyFlag

	// Configure cli app
	app := cli.NewApp()
	app.Name = "step"
	app.HelpName = "step"
	app.Usage = "plumbing for distributed systems"
	app.Version = config.Version()
	app.Commands = command.Retrieve()
	app.Flags = append(app.Flags, cli.HelpFlag)
	app.EnableBashCompletion = true
	app.Copyright = "(c) 2018 Smallstep Inc."

	// All non-successful output should be written to stderr
	app.Writer = os.Stderr
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
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

var sectionRe = regexp.MustCompile(`(?m:^##)`)

//var sectionRe = regexp.MustCompile(`^## [^\n]*$`)

func findSectionEnd(h, s string) int {
	start := strings.Index(s, fmt.Sprintf("## %s", h))
	if start == -1 {
		return start
	}
	nextSection := sectionRe.FindStringIndex(s[start+2:])
	if nextSection == nil {
		return len(s)
	}
	return start + 2 + nextSection[0]
}

// Convert some stuff that we can't easily write in help files because
//  backticks and raw strings don't mix:
// - "<foo>" to "`foo`"
// - "'''" to "```"
func markdownify(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '<':
			if b[i-1] != '\\' {
				b[i] = '`'
			}
		case '>':
			if b[i-1] != '\\' {
				b[i] = '`'
			}
		case '\'':
			if len(b) >= i+3 && string(b[i:i+3]) == "'''" {
				b[i] = '`'
				b[i+1] = '`'
				b[i+2] = '`'
				i += 2
			}
		}
	}
	return b
}

func helpPrinter(w io.Writer, templ string, data interface{}) {
	buf := new(bytes.Buffer)
	cli.HelpPrinterCustom(buf, templ, data, nil)
	//w.Write(buf.Bytes())
	s := string(markdownify(buf.Bytes()))
	// Move the OPTIONS section to the right place. urfave puts them at the end
	// of the file, we want them to be after POSITIONAL ARGUMENTS, DESCRIPTION,
	// USAGE, or NAME (in that order, depending on which sections exist).
	optLoc := strings.Index(s, "## OPTIONS")
	if optLoc != -1 {
		optEnd := findSectionEnd("OPTIONS", s)
		if optEnd != -1 {
			options := s[optLoc:optEnd]
			s = s[:optLoc] + s[optEnd:]
			if newLoc := findSectionEnd("POSITIONAL ARGUMENTS", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else if newLoc := findSectionEnd("DESCRIPTION", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else if newLoc := findSectionEnd("USAGE", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else if newLoc := findSectionEnd("NAME", s); newLoc != -1 {
				s = s[:newLoc] + options + s[newLoc:]
			} else {
				// Keep it at the end I guess :/.
				s = s + options
			}
		}
	}
	w.Write(usage.Render([]byte(s)))
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
	usage := fv.FieldByName("Usage").String()
	placeholder := placeholderString.FindString(usage)
	if placeholder == "" {
		placeholder = "<value>"
	}
	return cli.FlagNamePrefixer(fv.FieldByName("Name").String(), placeholder) + "\t" + usage
}
