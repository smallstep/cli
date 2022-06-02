//go:build js
// +build js

package offline

import (
	"errors"

	"github.com/urfave/cli"
)

var errNotSupported = errors.New("offline client not (yet) supported for js/wasm")

// TODO(hs): implement method stubs for unsupportedOfflineCA and
// return it in New()
type unsupportedOfflineCA struct{}

// New always return a nil instance of the CA interface and an
// error indicating offline mode is not (yet) support for the js/wasm 
// target.
func New(ctx *cli.Context, caConfig string) (CA, error) {
	return nil, errNotSupported
}
