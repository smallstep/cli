package policycontext

import (
	"context"
)

type policyLevelContextKey struct{}

type policyLevel int

const (
	authorityPolicyLevel policyLevel = iota + 1
	provisionerPolicyLevel
	acmePolicyLevel
)

// WithAuthorityPolicyLevel returns a new context.Context with
// parent ctx and authority policy level set.
func WithAuthorityPolicyLevel(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLevelContextKey{}, authorityPolicyLevel)
}

// IsAuthorityPolicyLevel returns if the context.Context has authority policy level.
func IsAuthorityPolicyLevel(ctx context.Context) bool {
	return isPolicyLevel(ctx, authorityPolicyLevel)
}

// WithProvisionerPolicyLevel returns a new context.Context with
// parent ctx and provisioner policy level set.
func WithProvisionerPolicyLevel(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLevelContextKey{}, provisionerPolicyLevel)
}

// IsProvisionerPolicyLevel returns if the context.Context has provisioner policy level.
func IsProvisionerPolicyLevel(ctx context.Context) bool {
	return isPolicyLevel(ctx, provisionerPolicyLevel)
}

// WithACMEPolicyLevel returns a new context.Context with
// parent ctx and ACME account policy level set.
func WithACMEPolicyLevel(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLevelContextKey{}, acmePolicyLevel)
}

// IsACMEPolicyLevel returns if the context.Context has ACME account policy level.
func IsACMEPolicyLevel(ctx context.Context) bool {
	return isPolicyLevel(ctx, acmePolicyLevel)
}

// isPolicyLevel checks if the context.Context has the specified policy level set.
func isPolicyLevel(ctx context.Context, level policyLevel) bool {
	v, _ := ctx.Value(policyLevelContextKey{}).(policyLevel)
	return v == level
}

type policyConfigurationTypeContextKey struct{}

type policyConfigurationType int

const (
	x509PolicyType policyConfigurationType = iota + 1
	sshHostPolicyType
	sshUserPolicyType
)

// WithX509Policy returns a new context.Context with
// parent ctx and X509 policy set.
func WithX509Policy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, x509PolicyType)
}

// IsX509Policy returns if the context.Context has X.509 policy set.
func IsX509Policy(ctx context.Context) bool {
	v, _ := ctx.Value(policyConfigurationTypeContextKey{}).(policyConfigurationType)
	return v == x509PolicyType
}

// WithSSHHostPolicy returns a context.Context with SSH host policy set.
func WithSSHHostPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, sshHostPolicyType)
}

// IsSSHHostPolicy returns if the context.Context has SSH host policy set.
func IsSSHHostPolicy(ctx context.Context) bool {
	v, _ := ctx.Value(policyConfigurationTypeContextKey{}).(policyConfigurationType)
	return v == sshHostPolicyType
}

// WithSSHUserPolicy returns a context.Context with SSH user policy set.
func WithSSHUserPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, sshUserPolicyType)
}

// IsSSHUserPolicy returns if context.Context has SSH user policy set.
func IsSSHUserPolicy(ctx context.Context) bool {
	v, _ := ctx.Value(policyConfigurationTypeContextKey{}).(policyConfigurationType)
	return v == sshUserPolicyType
}

type policyTypeContextKey struct{}

type policyType int

const (
	allowType policyType = iota + 1
	denyType
)

// WithAllow returns a context.Context with allow policy set.
func WithAllow(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyTypeContextKey{}, allowType)
}

// IsAllow returns if the context.Context has allow set.
func IsAllow(ctx context.Context) bool {
	v, _ := ctx.Value(policyTypeContextKey{}).(policyType)
	return v == allowType
}

// WithDeny returns a context.Context with deny set.
func WithDeny(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyTypeContextKey{}, denyType)
}

// IsDeny returns if context.Context has deny set.
func IsDeny(ctx context.Context) bool {
	v, _ := ctx.Value(policyTypeContextKey{}).(policyType)
	return v == denyType
}

func GetPrefixedCommandUsage(ctx context.Context, commandName string) string {
	usage := "step ca policy"

	switch {
	case IsAuthorityPolicyLevel(ctx):
		usage += " authority"
	case IsProvisionerPolicyLevel(ctx):
		usage += " provisioner"
	case IsACMEPolicyLevel(ctx):
		usage += " acme"
	default:
		panic("no policy level set")
	}

	switch {
	case IsX509Policy(ctx):
		usage += " x509"
	case IsSSHHostPolicy(ctx):
		usage += " ssh host"
	case IsSSHUserPolicy(ctx):
		usage += " ssh user"
	default:
		// noop; not every command using policycontext needs this to be set
		break
	}

	switch {
	case IsAllow(ctx):
		usage += " allow"
	case IsDeny(ctx):
		usage += " deny"
	default:
		// noop; not every command using policycontext needs this to be set
		break
	}

	return usage + " " + commandName
}
