package policycontext

import (
	"context"
)

type policyLevelContextKey struct{}

type policyLevel int

const (
	_ policyLevel = iota
	authorityPolicyLevel
	provisionerPolicyLevel
	acmePolicyLevel
)

// New is a helper that returns a new context.Context.
func New() context.Context {
	return context.Background()
}

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
	_ policyConfigurationType = iota
	x509Policy
	sshHostPolicy
	sshUserPolicy
)

func NewContextWithX509Policy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, x509Policy)
}

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

func NewContextWithSSHHostPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, sshHostPolicy)
}

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

func NewContextWithSSHUserPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyConfigurationTypeContextKey{}, sshUserPolicy)
}

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
	_ policy = iota
	allow
	deny
)

func NewContextWithAllow(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyContextKey{}, allow)
}

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

func NewContextWithDeny(ctx context.Context) context.Context {
	return context.WithValue(ctx, policyContextKey{}, deny)
}

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
