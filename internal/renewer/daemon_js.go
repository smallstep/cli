//go:build js
// +build js

package renewer

import (
	"errors"
	"time"
)

func (r *Renewer) Daemon(outFile string, next, expiresIn, renewPeriod time.Duration, afterRenew func() error) error {
	return errors.New("daemonizing not supported in js/wasm")
}
