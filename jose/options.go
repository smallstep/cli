package jose

type context struct {
	use, alg, kid    string
	subtle, insecure bool
	noDefaults       bool
}

// apply the options to the context and returns it.
func (ctx *context) apply(opts ...Option) *context {
	for _, opt := range opts {
		opt(ctx)
	}
	return ctx
}

// Option is the type used to add attributes to the context.
type Option func(ctx *context)

// WithUse adds the use claim to the context.
func WithUse(use string) Option {
	return func(ctx *context) {
		ctx.use = use
	}
}

// WithAlg adds the alg claim to the context.
func WithAlg(alg string) Option {
	return func(ctx *context) {
		ctx.alg = alg
	}
}

// WithKid adds the kid property to the context.
func WithKid(kid string) Option {
	return func(ctx *context) {
		ctx.kid = kid
	}
}

// WithSubtle marks the context as subtle.
func WithSubtle(subtle bool) Option {
	return func(ctx *context) {
		ctx.subtle = subtle
	}
}

// WithInsecure marks the context as insecure.
func WithInsecure(insecure bool) Option {
	return func(ctx *context) {
		ctx.insecure = insecure
	}
}

// WithNoDefaults avoids that the parser loads defaults values, specially the
// default algorithms.
func WithNoDefaults(val bool) Option {
	return func(ctx *context) {
		ctx.noDefaults = val
	}
}
