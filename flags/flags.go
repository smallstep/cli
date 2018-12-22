package flags

import (
	"time"

	"github.com/urfave/cli"
)

// Subtle is the flag required for delicate operations.
var Subtle = cli.BoolFlag{
	Name: "subtle",
}

// Insecure is the flag required on insecure operations
var Insecure = cli.BoolFlag{
	Name: "insecure",
}

// Force is a cli.Flag used to overwrite files.
var Force = cli.BoolFlag{
	Name:  "f,force",
	Usage: "Force the overwrite of files without asking.",
}

// ParseTimeOrDuration is a helper that returns the time or the current time
// with an extra duration. It's used in flags like --not-before, --not-after.
func ParseTimeOrDuration(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, true
	}

	var t time.Time
	if err := t.UnmarshalText([]byte(s)); err != nil {
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, false
		}
		t = time.Now().Add(d)
	}
	return t, true
}
