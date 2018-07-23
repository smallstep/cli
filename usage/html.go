package usage

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/smallstep/cli/errs"

	"github.com/urfave/cli"
)

func htmlHelpAction(ctx *cli.Context) error {
	addr := ctx.String("http")
	if addr == "" {
		return errs.RequiredFlag(ctx, "http")
	}

	fmt.Printf("Serving HTTP on %s ...\n", addr)
	return http.ListenAndServe(addr, &htmlHelpHandler{
		cliApp: ctx.App,
	})
}

type htmlHelpHandler struct {
	cliApp *cli.App
}

func (h *htmlHelpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := cli.NewContext(h.cliApp, nil, nil)

	// clean request URI
	requestURI := path.Clean(req.RequestURI)
	if requestURI == "/" {
		htmlHelpPrinter(w, htmlAppHelpTemplate, ctx.App)
		return
	}

	args := strings.Split(requestURI, "/")
	last := len(args) - 1
	lastName := args[last]
	subcmd := ctx.App.Commands
	parent := createParentCommand(ctx)
	for _, name := range args[:last] {
		for _, cmd := range subcmd {
			if cmd.HasName(name) {
				parent = cmd
				subcmd = cmd.Subcommands
				break
			}
		}
	}

	for _, cmd := range subcmd {
		if cmd.HasName(lastName) {
			cmd.HelpName = fmt.Sprintf("%s %s", ctx.App.HelpName, strings.Join(args, " "))
			parent.HelpName = fmt.Sprintf("%s %s", ctx.App.HelpName, strings.Join(args[:last], " "))

			ctx.Command = cmd
			if len(cmd.Subcommands) == 0 {
				htmlHelpPrinter(w, htmlCommandHelpTemplate, cmd)
				return
			}

			ctx.App = createCliApp(ctx, cmd)
			htmlHelpPrinter(w, htmlSubcommandHelpTemplate, ctx.App)
			return
		}
	}

	http.NotFound(w, req)
}

// htmlAppHelpTemplate contains the modified template for the main app
var htmlAppHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .Commands}} <command>{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Description}}

## STABILITY INDEX

FOO BAR BAZ

## DESCRIPTION
{{.Description}}{{end}}{{if .VisibleCommands}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
|||
|---|---|{{range .VisibleCommands}}
| **[{{join .Names ", "}}]({{.Name}}/)** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}{{end}}

## OPTIONS

{{range $index, $option := .VisibleFlags}}{{if $index}}
{{end}}{{$option}}
{{end}}{{end}}{{if .Copyright}}{{if len .Authors}}

## AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:

{{range $index, $author := .Authors}}{{if $index}}
{{end}}{{$author}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

## ONLINE

This documentation is available online at https://smallstep.com/documentation

## PRINTING

This documentation can be typeset for printing by running ...

A version of this document typeset for printing is available online at ...pdf

## VERSION

{{.Version}}{{end}}{{end}}

## COPYRIGHT

{{.Copyright}}
{{end}}
`

// SubcommandHelpTemplate contains the modified template for a sub command
// Note that the weird "|||\n|---|---|" syntax sets up a markdown table with empty headers.
var htmlSubcommandHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}** <command>{{if .VisibleFlags}} _[options]_{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Description}}

## DESCRIPTION

{{.Description}}{{end}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
|||
|---|---|{{range .VisibleCommands}}
| **[{{join .Names ", "}}](./{{.Name}}/)** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}

## OPTIONS

{{range .VisibleFlags}}
{{.}}
{{end}}{{end}}
`

// CommandHelpTemplate contains the modified template for a command
var htmlCommandHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .VisibleFlags}} _[options]_{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Category}}

## CATEGORY

{{.Category}}{{end}}{{if .Description}}

## DESCRIPTION

{{.Description}}{{end}}{{if .VisibleFlags}}

## OPTIONS

{{range .VisibleFlags}}
{{.}}
{{end}}{{end}}
`
