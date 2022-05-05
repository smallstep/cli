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

// NewContextWithAuthorityPolicyLevel returns a new context.Context with
// parent ctx and authority policy level set.
func NewContextWithAuthorityPolicyLevel(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLevelContextKey{}, authorityPolicyLevel)
}

// HasAuthorityPolicyLevel returns if the context.Context has authority policy level.
func HasAuthorityPolicyLevel(ctx context.Context) bool {
	return hasPolicyLevel(ctx, authorityPolicyLevel)
}

// NewContextWithProvisionerPolicyLevel returns a new context.Context with
// parent ctx and provisioner policy level set.
func NewContextWithProvisionerPolicyLevel(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLevelContextKey{}, provisionerPolicyLevel)
}

// HasProvisionerPolicyLevel returns if the context.Context has provisioner policy level.
func HasProvisionerPolicyLevel(ctx context.Context) bool {
	return hasPolicyLevel(ctx, provisionerPolicyLevel)
}

// NewContextWithACMEPolicyLevel returns a new context.Context with
// parent ctx and ACME account policy level set.
func NewContextWithACMEPolicyLevel(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyLevelContextKey{}, acmePolicyLevel)
}

// HasACMEPolicyLevel returns if the context.Context has ACME account policy level.
func HasACMEPolicyLevel(ctx context.Context) bool {
	return hasPolicyLevel(ctx, acmePolicyLevel)
}

// hasPolicyLevel checks if the context.Context has the specified policy level set.
func hasPolicyLevel(ctx context.Context, level policyLevel) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(policyLevelContextKey{})
	if _, ok := value.(policyLevel); ok {
		return value == level
	}
	return false
}

type policyConfigurationTypeContextKey struct{}

type policyConfigurationType int

const (
	x509Policy policyConfigurationType = iota + 1
	sshHostPolicy
	sshUserPolicy
)

func NewContextWithX509Policy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, x509Policy)
}

// HasX509Policy returns if the context.Context has X.509 policy set.
func HasX509Policy(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(policyConfigurationTypeContextKey{})
	if _, ok := value.(policyConfigurationType); ok {
		return value == x509Policy
	}
	return false
}

// NewContextWithSSHHostPolicy returns a context.Context with SSH host policy set.
func NewContextWithSSHHostPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, sshHostPolicy)
}

// HasSSHHostPolicy returns if the context.Context has SSH host policy set.
func HasSSHHostPolicy(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(policyConfigurationTypeContextKey{})
	if _, ok := value.(policyConfigurationType); ok {
		return value == sshHostPolicy
	}
	return false
}

// NewContextWithSSHUserPolicy returns a context.Context with SSH user policy set.
func NewContextWithSSHUserPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, sshUserPolicy)
}

// HasSSHUserPolicy returns if context.Context has SSH user policy set.
func HasSSHUserPolicy(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(policyConfigurationTypeContextKey{})
	if _, ok := value.(policyConfigurationType); ok {
		return value == sshUserPolicy
	}
	return false
}

type policyContextKey struct{}

type policy int

const (
	allow policy = iota + 1
	deny
)

// NewContextWithAllow returns a context.Context with allow policy set.
func NewContextWithAllow(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyContextKey{}, allow)
}

// HasAllow returns if the context.Context has allow set.
func HasAllow(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(policyContextKey{})
	if _, ok := value.(policy); ok {
		return value == allow
	}
	return false
}

// NewContextWithDeny returns a context.Context with deny set.
func NewContextWithDeny(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyContextKey{}, deny)
}

// HasDeny returns if context.Context has deny set.
func HasDeny(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(policyContextKey{})
	if _, ok := value.(policy); ok {
		return value == deny
	}
	return false
}
