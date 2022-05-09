package command

import (
	"context"
	"os"
)

// ShouldBeHidden returns if a cli.Command should be hidden from
// help or not. Currently the only condition is the presence of
// the STEPBETA environment variable.
// TODO(hs): provide more logic/conditions for hiding/showing
// the Command? We may want to retrieve info from the context
// when it's used in more parts of the CLI; not just in the
// policy subcommand.
func ShouldBeHidden(ctx context.Context) bool {
	return os.Getenv("STEPBETA") != "1"
}
