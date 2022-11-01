package command

import (
	"context"

	"github.com/urfave/cli"
)

// InjectContext injects an existing Context as the first middleware
// and then wraps a function with middleware using that context. It
// returns a cli.ActionFunc with the cli.Context added to the Context.
// By injecting the existing context as the first middleware, we ensure
// that it's the Context all later middlewares operate on.
func InjectContext(injectedCtx context.Context, fn func(context.Context) error, middleware ...func(context.Context) (context.Context, error)) cli.ActionFunc {
	injectedMiddleware := []func(context.Context) (context.Context, error){
		func(context.Context) (context.Context, error) {
			return injectedCtx, nil
		},
	}
	injectedMiddleware = append(injectedMiddleware, middleware...)
	//nolint:contextcheck // context is injected in fn
	return wrap(fn, injectedMiddleware...)
}

type cliCtxKey struct{}

// withCLIContext adds a cli.Context to the Context.
func withCLIContext(ctx context.Context, clictx *cli.Context) context.Context {
	return context.WithValue(ctx, cliCtxKey{}, clictx)
}

// CLIContextFromContext returns a pointer to a cli.Context
// It panics when the cli.Context is not set.
func CLIContextFromContext(ctx context.Context) *cli.Context {
	return ctx.Value(cliCtxKey{}).(*cli.Context)
}

// wrap wraps a function with middleware using a new context. It returns a cli.ActionFunc with
// the cli.Context added to the Context.
func wrap(fn func(context.Context) error, middleware ...func(context.Context) (context.Context, error)) cli.ActionFunc {
	return func(clictx *cli.Context) error {
		ctx := context.Background()

		// apply middleware to the new context
		for _, fn := range middleware {
			var err error
			if ctx, err = fn(ctx); err != nil {
				return err
			}
		}

		ctx = withCLIContext(ctx, clictx)

		return fn(ctx)
	}
}
