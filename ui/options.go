package ui

import (
	"fmt"

	"github.com/manifoldco/promptui"
)

type options struct {
	mask            rune
	defaultValue    string
	allowEdit       bool
	promptTemplates *promptui.PromptTemplates
	selectTemplates *promptui.SelectTemplates
	validateFunc    promptui.ValidateFunc
}

func (o *options) apply(opts []Option) *options {
	for _, fn := range opts {
		fn(o)
	}
	return o
}

// Option is the type of the functions that modify the prompt options.
type Option func(*options)

// WithMask adds a mask to a prompt.
func WithMask(r rune) Option {
	return func(o *options) {
		o.mask = r
	}
}

// WithDefaultValue adds a custom string as the default value.
func WithDefaultValue(s string) Option {
	return func(o *options) {
		o.defaultValue = s
	}
}

// WithAllowEdit if true, let's the user edit the default value set.
func WithAllowEdit(b bool) Option {
	return func(o *options) {
		o.allowEdit = b
	}
}

// WithPromptTemplates adds a custom template to a prompt.
func WithPromptTemplates(t *promptui.PromptTemplates) Option {
	return func(o *options) {
		o.promptTemplates = t
	}
}

// WithSelectTemplates adds a custom template to a select.
func WithSelectTemplates(t *promptui.SelectTemplates) Option {
	return func(o *options) {
		o.selectTemplates = t
	}
}

// WithValidateFunc adds a custom validation function to a prompt.
func WithValidateFunc(fn func(string) error) Option {
	return func(o *options) {
		o.validateFunc = fn
	}
}

// WithValidateNotEmpty adds a custom validation function to a prompt that
// checks that the propted string is not empty.
func WithValidateNotEmpty() Option {
	return WithValidateFunc(NotEmpty())
}

// NotEmpty is a validation function that checks that the prompted string is not
// empty.
func NotEmpty() promptui.ValidateFunc {
	return func(s string) error {
		if len(s) > 0 {
			return nil
		}
		return fmt.Errorf("value is empty")
	}
}
