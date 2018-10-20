package ui

import (
	"fmt"

	"github.com/manifoldco/promptui"
)

// PrintSelectedTemplate returns the default template used in PrintSelected.
func PrintSelectedTemplate() string {
	return fmt.Sprintf(`{{ "%s" | green }} {{ .Name | bold }}{{ ":" | bold }} {{ .Value }}`, promptui.IconGood) + "\n"
}

// PromptTemplates is the default style for a prompt.
func PromptTemplates() *promptui.PromptTemplates {
	bold := promptui.Styler(promptui.FGBold)
	return &promptui.PromptTemplates{
		Prompt:  fmt.Sprintf("%s {{ . | bold }}%s ", promptui.IconInitial, bold(":")),
		Success: fmt.Sprintf("%s {{ . | bold }}%s ", bold(promptui.IconGood), bold(":")),
		// Confirm: fmt.Sprintf(`{{ "%s" | bold }} {{ . | bold }}? {{ "[]" | faint }} `, promptui.IconInitial),
		Valid:   fmt.Sprintf("%s {{ . | bold }}%s ", bold(promptui.IconGood), bold(":")),
		Invalid: fmt.Sprintf("%s {{ . | bold }}%s ", bold(promptui.IconBad), bold(":")),
	}
}

// SelectTemplates returns the default promptui.SelectTemplate for string
// slices. The given name is the prompt of the selected option.
func SelectTemplates(name string) *promptui.SelectTemplates {
	return &promptui.SelectTemplates{
		Label:    fmt.Sprintf("%s {{ . }}: ", promptui.IconInitial),
		Active:   fmt.Sprintf("%s {{ . | underline }}", promptui.IconSelect),
		Inactive: "  {{ . }}",
		Selected: fmt.Sprintf(`{{ "%s" | green }} {{ "%s:" | bold }} {{ .Name }}`, promptui.IconGood, name),
	}
}

// NamedSelectTemplates returns the default promptui.SelectTemplate for struct
// slices with a name property. The given name is the prompt of the selected
// option.
func NamedSelectTemplates(name string) *promptui.SelectTemplates {
	return &promptui.SelectTemplates{
		Label:    fmt.Sprintf("%s {{.Name}}: ", promptui.IconInitial),
		Active:   fmt.Sprintf("%s {{ .Name | underline }}", promptui.IconSelect),
		Inactive: "  {{.Name}}",
		Selected: fmt.Sprintf(`{{ "%s" | green }} {{ "%s:" | bold }} {{ .Name }}`, promptui.IconGood, name),
	}
}
