package command

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestCLIContextFromContext(t *testing.T) {
	t.Parallel()

	exp := new(cli.Context)

	got := CLIContextFromContext(withCLIContext(context.Background(), exp))
	assert.Same(t, exp, got)
}

func TestCLIContextFromContextPanics(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { CLIContextFromContext(context.Background()) })
}

func TestInjectContext(t *testing.T) {
	t.Parallel()

	fnCalled := false

	type contextKey struct{}

	ctx := context.Background()
	ctx = context.WithValue(ctx, contextKey{}, true)

	fn := func(ctx context.Context) error {
		assert.True(t, ctx.Value(contextKey{}).(bool))
		clictx := CLIContextFromContext(ctx)
		assert.NotNil(t, clictx)
		fnCalled = true
		return nil
	}

	got := InjectContext(ctx, fn)

	assert.NotNil(t, got)

	// execute the function to ensure injected context is OK
	err := got(new(cli.Context))
	assert.NoError(t, err)
	assert.True(t, fnCalled)
}

func TestInjectContextWithMiddleware(t *testing.T) {
	t.Parallel()

	fnCalled := false

	type contextKey struct{}
	type firstMiddlewareContextKey struct{}
	type secondMiddlewareContextKey struct{}

	ctx := context.Background()
	ctx = context.WithValue(ctx, contextKey{}, true)

	fn := func(ctx context.Context) error {
		assert.True(t, ctx.Value(contextKey{}).(bool))
		clictx := CLIContextFromContext(ctx)
		assert.NotNil(t, clictx)
		assert.Equal(t, 42, ctx.Value(firstMiddlewareContextKey{}).(int))
		assert.Equal(t, "value", ctx.Value(secondMiddlewareContextKey{}).(string))
		fnCalled = true
		return nil
	}

	middleware := []func(context.Context) (context.Context, error){
		func(ctx context.Context) (context.Context, error) {
			return context.WithValue(ctx, firstMiddlewareContextKey{}, 42), nil
		},
		func(ctx context.Context) (context.Context, error) {
			return context.WithValue(ctx, secondMiddlewareContextKey{}, "value"), nil
		},
	}

	got := InjectContext(ctx, fn, middleware...)

	assert.NotNil(t, got)

	// execute the function to ensure injected context is OK
	err := got(new(cli.Context))
	assert.NoError(t, err)
	assert.True(t, fnCalled)
}

func TestInjectContextWithMiddlewareError(t *testing.T) {
	t.Parallel()

	fnCalled := false

	type contextKey struct{}

	ctx := context.Background()
	ctx = context.WithValue(ctx, contextKey{}, true)

	fn := func(ctx context.Context) error {
		assert.True(t, ctx.Value(contextKey{}).(bool))
		clictx := CLIContextFromContext(ctx)
		assert.NotNil(t, clictx)
		fnCalled = true
		return nil
	}

	var middlewareError = errors.New("a middleware error")

	middleware := []func(context.Context) (context.Context, error){
		func(context.Context) (context.Context, error) {
			assert.True(t, ctx.Value(contextKey{}).(bool))
			return nil, middlewareError
		},
	}

	got := InjectContext(ctx, fn, middleware...)

	assert.NotNil(t, got)

	// execute the function and verify middleware resulted in error
	err := got(new(cli.Context))
	assert.Error(t, err)
	assert.Equal(t, middlewareError, err)
	assert.False(t, fnCalled) // fn is not called because of middleware error
}
