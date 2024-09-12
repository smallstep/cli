# How to add a new Command

Before making any changes, please consult the [CLI style guide](https://github.com/urfave/cli)!

### Package Layout

The [`urfave/cli`](https://github.com/urfave/cli) package that forms the basis
of Step CLI supports N-levels of command hierarchy. Each level of the hierarchy
should exist within its own package if possible. For example, `version` and
`help` exist inside their own packages inside the top-level `command` package.

Any package used by a command but does not contain explicit business logic
directly related to the command should exist in the top-level of this
repository. For example, the `github.com/smallstep/cli/flags` and
`github.com/smallstep/cli-utils/errs` package are used by many different commands and
contain functionality for defining flags and creating/manipulating errors.

### Adding a Command

Once you figured out where to add the command inside the package hierarchy you
must register the command. This way the command *can* be made available if
desired inside the `cmd/step/main.go`.

An example of defining a command and registering it:

```golang
package validate

import (
  "github.com/urfave/cli"

  "github.com/smallstep/cli/command"
  "github.com/smallstep/cli/flags"
)

func init() {
  cmd := cli.Command{
    Name: "validate",
    Usage: "Returns whether or not the provided token is valid",
    Flags: []cli.Flag{
      flags.Token("The one-time token value to validate"),
    },
    Action: validate,
  }

  command.Register(validate)
}
```

Once this is done, you then must import the pkg inside `cmd/step/main.go` so
the packages `init` method is run appropriately. This only needs to be done for
top-level commands.

```golang
package main

import (
  "github.com/urfave/cli"

  _ "github.com/smallstep/cli/validate"
)
```

This will ensure that the `smallstep/cli/validate` package is initialized
and thus registered with the `smallstep/cli/command`.

### Usage, Flags, Errors, and Prompts

There are three packages which contain functionality to make writing commands easier:

- `github.com/smallstep/cli/flags`
- `github.com/smallstep/cli/prompts`
- `github.com/smallstep/cli-utils/errs`
- `github.com/smallstep/cli-utils/usage`

The usage package is used to extend the default documentation provided by
`urfave/cli` by enabling us to document arguments, whether they are optional or
required, and ensuring they're printed out as a part of the `step help` or
`step <command> -h` flow. If you need to add a different type of annotation to
document an argument just add it to the `usage.Argument` struct!

When you add a flag, look into the preexisting ones inside the `flags`
package. Could you use one of the preexisting flags in order to reduce
duplication? If not, make sure to add a flag so it could be used in future!

The `errs` package contains functionality for defining and working with errors
to ensure they are mutated properly into a `urfave/cli.ExitError` which ensures
the process returns an appropriate exit code on termination. When you create an
error, consider whether or not it's general and could be predefined inside the
`errs` package. Errors that are specific to the command itself should exist
only inside that commands respective package.

The `prompts` package is a small wrapper around the various different types of
prompts used by the commands. If you need a new prompt, consider adding a new
function to this package to tailor the prompt for the step cli. This way other
commands can adopt the step aesthetic as new functionality is introduced.

### Hiding a Command

Sometimes it's desirable to prevent a command from showing up in the help menu
because it's been deprecated *or* it's not ready for users to leverage. This
can be achieved by setting the `Hidden` property on the `cli.Command` struct to
`true`.
