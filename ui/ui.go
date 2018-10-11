package ui

import (
	"fmt"
	"os"

	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
)

// stderr implements an io.WriteCloser that skips the terminal bell character
// (ASCII code 7), and writes the rest to os.Stderr. It's used to replace
// readline.Stdout, that is the package used by promptui to display the prompts.
type stderr struct{}

// Write implements an io.WriterCloser over os.Stderr, but it skips the terminal
// bell character.
func (s *stderr) Write(b []byte) (int, error) {
	if len(b) == 1 && b[0] == readline.CharBell {
		return 0, nil
	}
	return os.Stderr.Write(b)
}

// Close implements an io.WriterCloser over os.Stderr.
func (s *stderr) Close() error {
	return os.Stderr.Close()
}

func init() {
	readline.Stdout = &stderr{}
}

// SelectTemplate returns the default promptui.SelectTemplate.
func SelectTemplate(name string) *promptui.SelectTemplates {
	return &promptui.SelectTemplates{
		Label:    fmt.Sprintf("%s {{.Name}}: ", promptui.IconInitial),
		Active:   fmt.Sprintf("%s {{ .Name | underline }}", promptui.IconSelect),
		Inactive: "  {{.Name}}",
		Selected: fmt.Sprintf(`{{ "%s" | green }} {{ "%s:" | bold }} {{ .Name }}`, promptui.IconGood, name),
	}
}
