package usage

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"text/template"
	"unicode"

	md "github.com/smallstep/cli/pkg/blackfriday"
	"github.com/urfave/cli"
)

var sectionRe = regexp.MustCompile(`(?m:^##)`)
var sectionNameRe = regexp.MustCompile(`(?m:^## [^\n]+)`)
var indentRe = regexp.MustCompile(`(?m:^:[^\n]+)`)
var definitionListRe = regexp.MustCompile(`(?m:^[\t ]+\*\*[^\*]+\*\*[^\n]*\s+:[^\n]+)`)

//var sectionRe = regexp.MustCompile(`^## [^\n]*$`)

type frontmatterData struct {
	Data     interface{}
	Parent   string
	Children []string
}

// HelpPrinter overwrites cli.HelpPrinter and prints the formatted help to the terminal.
func HelpPrinter(w io.Writer, templ string, data interface{}) {
	b := helpPreprocessor(w, templ, data, false)
	w.Write(Render(b))
}

func htmlHelpPrinter(w io.Writer, templ string, data interface{}) []byte {
	b := helpPreprocessor(w, templ, data, true)
	w.Write([]byte(`<html><head><title>step command line documentation</title>`))
	w.Write([]byte(`<link href="/style.css" rel="stylesheet" type="text/css">`))
	w.Write([]byte(`</head><body><div class="wrapper markdown-body command">`))
	html := md.Run(b)
	w.Write(html)
	w.Write([]byte(`</div></body></html>`))

	return html
}

func markdownHelpPrinter(w io.Writer, templ string, parent string, data interface{}) {
	b := helpPreprocessor(w, templ, data, true)

	frontmatter := frontmatterData{
		Data:   data,
		Parent: parent,
	}

	if app, ok := data.(*cli.App); ok {
		for _, cmd := range app.Commands {
			frontmatter.Children = append(frontmatter.Children, cmd.Name)
		}
	}

	var frontMatterTemplate = `---
layout: auto-doc
title: {{.Data.HelpName}}
menu:
  docs:
{{- if .Parent}}
    parent: {{.Parent}}
{{- end }}
{{- if .Children }}
    children:
{{- range .Children }}
      - {{.}}
{{- end }}
{{- end }}
---

`
	t, err := template.New("frontmatter").Parse(frontMatterTemplate)
	if err != nil {
		panic(err)
	}
	err = t.Execute(w, frontmatter)
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func helpPreprocessor(w io.Writer, templ string, data interface{}, applyRx bool) []byte {
	buf := new(bytes.Buffer)
	cli.HelpPrinterCustom(buf, templ, data, nil)
	//w.Write(buf.Bytes())
	// s := string(markdownify(buf.Bytes()))
	s := markdownify(buf)
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

	if applyRx {
		// Keep capitalized only the first letter in arguments names.
		s = sectionNameRe.ReplaceAllStringFunc(s, func(s string) string {
			return s[0:4] + strings.ToLower(s[4:])
		})
		// Remove `:` at the start of a line.
		s = indentRe.ReplaceAllStringFunc(s, func(s string) string {
			return strings.TrimSpace(s[1:])
		})
		// Convert lines like:
		//   **Foo**
		//   : Bar zar ...
		// To:
		//   - **Foo**: Bar zar ...
		s = definitionListRe.ReplaceAllStringFunc(s, func(s string) string {
			i := strings.Index(s, "\n")
			j := strings.Index(s, ":")
			return "- " + strings.TrimSpace(s[:i]) + ": " + strings.TrimSpace(s[j+1:])
		})
	}

	return []byte(s)
}

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
func markdownify(r *bytes.Buffer) string {
	const escapeByte = byte('\\')
	var last byte
	var inCode bool

	w := new(bytes.Buffer)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return w.String()
		}
	loop:
		switch b {
		case '<':
			if last != escapeByte && !inCode {
				w.WriteByte('`')
			} else {
				w.WriteByte(b)
			}
		case '>':
			if last != escapeByte && !inCode {
				w.WriteByte('`')
			} else {
				w.WriteByte(b)
			}
		case '\'':
			b1, _ := r.ReadByte()
			b2, _ := r.ReadByte()
			if b1 == b && b2 == b {
				w.WriteString("```")
				if !inCode {
					if n, _, err := r.ReadRune(); err == nil {
						if unicode.IsSpace(n) {
							w.WriteString("shell")
						}
						r.UnreadRune()
					}
				}
				inCode = !inCode
			} else {
				// We can only unread the last one (b2)
				w.WriteByte(b)
				r.UnreadByte()
				b = b1
				last = b
				goto loop
			}
		case '*':
			if inCode {
				if b1, _ := r.ReadByte(); b1 != '*' {
					w.WriteByte(b)
					w.UnreadByte()
				}
			} else {
				w.WriteByte(b)
			}
		case escapeByte:
			if last == escapeByte {
				w.WriteByte(escapeByte)
				b = 0
			} else {
				if n, _, err := r.ReadRune(); err == nil {
					if unicode.IsSpace(n) {
						w.WriteByte(escapeByte)
					}
					r.UnreadRune()
				}
			}
		case 0: // probably because io.EOF
		default:
			w.WriteByte(b)
		}
		last = b
	}
}
