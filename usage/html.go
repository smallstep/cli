package usage

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func httpHelpAction(ctx *cli.Context) error {
	addr := ctx.String("http")
	if addr == "" {
		return errs.RequiredFlag(ctx, "http")
	}

	fmt.Printf("Serving HTTP on %s ...\n", addr)
	return http.ListenAndServe(addr, &htmlHelpHandler{
		cliApp: ctx.App,
	})
}

func markdownHelpAction(ctx *cli.Context) error {
	dir := path.Clean(ctx.String("markdown"))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errs.FileError(err, dir)
	}

	isHugo := ctx.Bool("hugo")

	// app index
	index := path.Join(dir, "index.md")
	w, err := os.Create(index)
	if err != nil {
		return errs.FileError(err, index)
	}
	markdownHelpPrinter(w, mdAppHelpTemplate, "", ctx.App)
	if err := w.Close(); err != nil {
		return errs.FileError(err, index)
	}

	// Subcommands
	for _, cmd := range ctx.App.Commands {
		if err := markdownHelpCommand(ctx.App, cmd, cmd, path.Join(dir, cmd.Name), isHugo); err != nil {
			return err
		}
	}
	return nil
}

func markdownHelpCommand(app *cli.App, cmd cli.Command, parent cli.Command, base string, isHugo bool) error {
	if err := os.MkdirAll(base, 0755); err != nil {
		return errs.FileError(err, base)
	}

	fileName := "index.md"
	// preserve jekyll compatibility for transition period
	if isHugo && len(cmd.Subcommands) > 0 {
		fileName = "_index.md"
	}

	index := path.Join(base, fileName)
	w, err := os.Create(index)
	if err != nil {
		return errs.FileError(err, index)
	}

	parentName := parent.HelpName
	if cmd.HelpName == parent.HelpName {
		parentName = "step"
	}

	if len(cmd.Subcommands) == 0 {
		markdownHelpPrinter(w, mdCommandHelpTemplate, parentName, cmd)
		return errs.FileError(w.Close(), index)
	}

	ctx := cli.NewContext(app, nil, nil)
	ctx.App = createCliApp(ctx, cmd)
	markdownHelpPrinter(w, mdSubcommandHelpTemplate, parentName, ctx.App)
	if err := w.Close(); err != nil {
		return errs.FileError(err, index)
	}

	for _, sub := range cmd.Subcommands {
		sub.HelpName = fmt.Sprintf("%s %s", cmd.HelpName, sub.Name)
		if err := markdownHelpCommand(app, sub, cmd, path.Join(base, sub.Name), isHugo); err != nil {
			return err
		}
	}

	return nil
}

func htmlHelpAction(ctx *cli.Context) error {
	dir := path.Clean(ctx.String("html"))

	if err := os.MkdirAll(dir, 0755); err != nil {
		return errs.FileError(err, dir)
	}

	// app index
	index := path.Join(dir, "index.html")
	w, err := os.Create(index)
	if err != nil {
		return errs.FileError(err, index)
	}

	tophelp := htmlHelpPrinter(w, mdAppHelpTemplate, ctx.App)
	var report *Report
	if ctx.IsSet("report") {
		report = NewReport(ctx.App.Name, tophelp)
	}

	if err := w.Close(); err != nil {
		return errs.FileError(err, index)
	}

	// css style
	cssFile := path.Join(dir, "style.css")
	if err := ioutil.WriteFile(cssFile, []byte(css), 0666); err != nil {
		return errs.FileError(err, cssFile)
	}

	// Subcommands
	for _, cmd := range ctx.App.Commands {
		if err := htmlHelpCommand(ctx.App, cmd, path.Join(dir, cmd.Name), report); err != nil {
			return err
		}
	}

	// report
	if report != nil {
		repjson := path.Join(dir, "report.json")
		rjw, err := os.Create(repjson)
		if err != nil {
			return errs.FileError(err, repjson)
		}

		if err := report.Write(rjw); err != nil {
			return err
		}

		if err := rjw.Close(); err != nil {
			return errs.FileError(err, repjson)
		}
	}

	return nil
}

func htmlHelpCommand(app *cli.App, cmd cli.Command, base string, report *Report) error {
	if err := os.MkdirAll(base, 0755); err != nil {
		return errs.FileError(err, base)
	}

	index := path.Join(base, "index.html")
	w, err := os.Create(index)
	if err != nil {
		return errs.FileError(err, index)
	}

	if len(cmd.Subcommands) == 0 {
		cmdhelp := htmlHelpPrinter(w, mdCommandHelpTemplate, cmd)

		if report != nil {
			report.Process(cmd.HelpName, cmdhelp)
		}

		return errs.FileError(w.Close(), index)
	}

	ctx := cli.NewContext(app, nil, nil)
	ctx.App = createCliApp(ctx, cmd)
	subhelp := htmlHelpPrinter(w, mdSubcommandHelpTemplate, ctx.App)

	if report != nil {
		report.Process(cmd.HelpName, subhelp)
	}

	if err := w.Close(); err != nil {
		return errs.FileError(err, index)
	}

	for _, sub := range cmd.Subcommands {
		sub.HelpName = fmt.Sprintf("%s %s", cmd.HelpName, sub.Name)
		if err := htmlHelpCommand(app, sub, path.Join(base, sub.Name), report); err != nil {
			return err
		}
	}

	return nil
}

type htmlHelpHandler struct {
	cliApp *cli.App
}

func (h *htmlHelpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := cli.NewContext(h.cliApp, nil, nil)

	// clean request URI
	requestURI := path.Clean(req.RequestURI)
	if requestURI == "/" {
		htmlHelpPrinter(w, mdAppHelpTemplate, ctx.App)
		return
	}

	if requestURI == "/style.css" {
		w.Header().Set("Content-Type", `text/css; charset="utf-8"`)
		w.Write([]byte(css))
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
				htmlHelpPrinter(w, mdCommandHelpTemplate, cmd)
				return
			}

			ctx.App = createCliApp(ctx, cmd)
			htmlHelpPrinter(w, mdSubcommandHelpTemplate, ctx.App)
			return
		}
	}

	http.NotFound(w, req)
}

// AppHelpTemplate contains the modified template for the main app
var mdAppHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

'''raw
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .Commands}} <command>{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments]{{end}}{{end}}
'''
{{- if .Description}}

## DESCRIPTION
{{.Description}}{{end}}{{if .VisibleCommands}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
| Name | Usage |
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

## VERSION

{{.Version}}{{end}}{{end}}

## COPYRIGHT

{{.Copyright}}
{{end}}
`

// SubcommandHelpTemplate contains the modified template for a sub command
// Note that the weird "|||\n|---|---|" syntax sets up a markdown table with empty headers.
var mdSubcommandHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

'''raw
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}** <command>{{if .VisibleFlags}} [options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments]{{end}}{{end}}
'''
{{- if .Description}}

## DESCRIPTION

{{.Description}}{{end}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
| Name | Usage |
|---|---|{{range .VisibleCommands}}
| **[{{join .Names ", "}}]({{.Name}}/)** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}

## OPTIONS

{{range .VisibleFlags}}
{{.}}
{{end}}{{end}}
`

// CommandHelpTemplate contains the modified template for a command
var mdCommandHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE

'''raw
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .VisibleFlags}} [options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments]{{end}}{{end}}
'''
{{- if .Category}}

## CATEGORY

{{.Category}}{{end}}{{if .Description}}

## DESCRIPTION

{{.Description}}{{end}}{{if .VisibleFlags}}

## OPTIONS

{{range .VisibleFlags}}
{{.}}
{{end}}{{end}}
`
