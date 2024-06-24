//go:build tools

package cli

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "golang.org/x/tools/cmd/goimports"
	_ "gotest.tools/gotestsum"
)
