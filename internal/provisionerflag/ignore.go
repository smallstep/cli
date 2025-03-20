package provisionerflag

import (
	"sync/atomic"
)

var disabled atomic.Bool

// Ignore marks the provisionerflag to be ignored
func Ignore() {
	disabled.Store(true)
}

// ShouldBeIgnored returns true if the provisioner flag should be ignored
func ShouldBeIgnored() bool {
	return disabled.Load()
}
