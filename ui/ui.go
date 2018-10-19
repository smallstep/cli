package ui

import (
	"os"
	"syscall"

	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
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

// Prompt creates a runs a promptui.Prompt with the given label.
func Prompt(label string, opts ...Option) (string, error) {
	clean, err := preparePromptTerminal()
	if err != nil {
		return "", err
	}
	defer clean()

	o := &options{
		promptTemplates: PromptTemplates(),
	}
	o.apply(opts)

	prompt := &promptui.Prompt{
		Label:     label,
		Default:   o.defaultValue,
		AllowEdit: o.allowEdit,
		Validate:  o.validateFunc,
		Templates: o.promptTemplates,
	}
	value, err := prompt.Run()
	if err != nil {
		return "", errors.Wrap(err, "error reading prompt")
	}
	return value, nil
}

// PromptPassword creates a runs a promptui.Prompt with the given label. This
// prompt will mask the key entries with \r.
func PromptPassword(label string, opts ...Option) ([]byte, error) {
	clean, err := preparePromptTerminal()
	if err != nil {
		return nil, err
	}
	defer clean()

	o := &options{
		mask:            '\r',
		promptTemplates: PromptTemplates(),
	}
	o.apply(opts)

	prompt := &promptui.Prompt{
		Label:     label,
		Mask:      o.mask,
		Default:   o.defaultValue,
		AllowEdit: o.allowEdit,
		Validate:  o.validateFunc,
		Templates: o.promptTemplates,
	}
	pass, err := prompt.Run()
	if err != nil {
		return nil, errors.Wrap(err, "error reading password")
	}
	return []byte(pass), nil
}

// PromptPasswordGenerate creaes a runs a promptui.Prompt with the given label.
// This prompt will mask the key entries with \r. If the result password length
// is 0, it will generate a new prompt with a generated password that can be
// edited.
func PromptPasswordGenerate(label string, opts ...Option) ([]byte, error) {
	pass, err := PromptPassword(label, opts...)
	if err != nil || len(pass) > 0 {
		return pass, err
	}
	passString, err := randutil.ASCII(32)
	if err != nil {
		return nil, err
	}
	passString, err = Prompt("Password", WithDefaultValue(passString), WithAllowEdit(true), WithValidateNotEmpty())
	if err != nil {
		return nil, err
	}
	return []byte(passString), nil
}

// Select creates and runs a promptui.Select with the given label and items.
func Select(label string, items interface{}, opts ...Option) (int, string, error) {
	clean, err := prepareSelectTerminal()
	if err != nil {
		return 0, "", err
	}
	defer clean()

	o := &options{
		selectTemplates: SelectTemplates(label),
	}
	o.apply(opts)

	prompt := &promptui.Select{
		Label:     label,
		Items:     items,
		Templates: o.selectTemplates,
	}
	return prompt.Run()
}

func preparePromptTerminal() (func(), error) {
	nothing := func() {}
	if !readline.IsTerminal(syscall.Stdin) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nothing, errors.Wrap(err, "error allocating terminal")
		}
		clean := func() {
			tty.Close()
		}

		fd := int(tty.Fd())
		state, err := readline.MakeRaw(fd)
		if err != nil {
			defer clean()
			return nothing, errors.Wrap(err, "error making raw terminal")
		}
		stdin := readline.Stdin
		readline.Stdin = tty
		clean = func() {
			readline.Stdin = stdin
			readline.Restore(fd, state)
			tty.Close()
		}
		return clean, nil
	}

	return nothing, nil
}

func prepareSelectTerminal() (func(), error) {
	nothing := func() {}
	if !readline.IsTerminal(syscall.Stdin) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nothing, errors.Wrap(err, "error allocating terminal")
		}
		clean := func() {
			tty.Close()
		}

		fd := int(tty.Fd())
		state, err := readline.MakeRaw(fd)
		if err != nil {
			defer clean()
			return nothing, errors.Wrap(err, "error making raw terminal")
		}
		stdin := os.Stdin
		os.Stdin = tty
		clean = func() {
			os.Stdin = stdin
			readline.Restore(fd, state)
			tty.Close()
		}
		return clean, nil
	}

	return nothing, nil
}
