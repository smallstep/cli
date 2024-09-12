package completion

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
)

func init() {
	cmd := cli.Command{
		Name:      "completion",
		Usage:     "print the shell completion script",
		UsageText: "**step completion** <shell>",
		Description: `**step completion** command prints the shell completion script.

## POSITIONAL ARGUMENTS

<shell>
: The shell program. Supports bash, zsh, and fish.

## EXAMPLES

Add bash completion for the current user.
'''
$ step completion bash >> ~/.bash_completion
'''

Add fish completions for the current user.
'''
$ step completion fish | source
'''
`,
		Flags: []cli.Flag{
			flags.HiddenNoContext,
		},
		Action: Completion,
		BashComplete: func(c *cli.Context) {
			if c.NArg() > 0 {
				return
			}
			fmt.Println("bash")
			fmt.Println("zsh")
			fmt.Println("fish")
		},
	}

	command.Register(cmd)
}

var bash = `# bash completion for step
_step_cli_bash_autocomplete() {
	local cur opts base
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	if [[ "$cur" == "-"* ]]; then
		opts=$( ${COMP_WORDS[@]:0:$COMP_CWORD} ${cur} --generate-bash-completion )
	else
		opts=$( ${COMP_WORDS[@]:0:$COMP_CWORD} --generate-bash-completion )
	fi
	COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
	return 0
}

complete -o bashdefault -o default -F _step_cli_bash_autocomplete step

`

var zsh = `#compdef step

_step() {

  local -a opts
  local cur
  cur=${words[-1]}
  if [[ "$cur" == "-"* ]]; then
    opts=("${(@f)$(_CLI_ZSH_AUTOCOMPLETE_HACK=1 ${words[@]:0:#words[@]-1} ${cur} --generate-bash-completion)}")
  else
    opts=("${(@f)$(_CLI_ZSH_AUTOCOMPLETE_HACK=1 ${words[@]:0:#words[@]-1} --generate-bash-completion)}")
  fi

  if [[ "${opts[1]}" != "" ]]; then
    _describe 'values' opts
  else
    _files
  fi

  return
}

compdef _step step

`

func Completion(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	shell := ctx.Args().First()

	switch shell {
	case "bash":
		fmt.Print(bash)
	case "zsh":
		fmt.Print(zsh)
	case "fish":
		fish, err := ctx.App.ToFishCompletion()
		if err != nil {
			return fmt.Errorf("error creating fish completion: %w", err)
		}
		fmt.Print(fish)
	default:
		return errors.Errorf("unsupported shell %s", shell)
	}

	return nil
}
