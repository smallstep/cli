package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"go.step.sm/cli-utils/errs"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/internal/command"
)

func retrieveAndInitializePolicy(ctx context.Context, client *ca.AdminClient) (*linkedca.Policy, error) {

	var (
		policy *linkedca.Policy
		err    error
	)

	clictx := command.CLIContextFromContext(ctx)
	provisioner := clictx.String("provisioner")
	reference := clictx.String("reference")
	keyID := clictx.String("key-id")

	switch {
	case policycontext.HasAuthorityPolicyLevel(ctx):
		policy, err = client.GetAuthorityPolicy()
	case policycontext.HasProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		policy, err = client.GetProvisionerPolicy(provisioner)
	case policycontext.HasACMEPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return nil, errs.RequiredOrFlag(clictx, "reference", "key-id")
		}
		policy, err = client.GetACMEPolicy(provisioner, reference, keyID)
	default:
		panic("no context for policy retrieval set")
	}

	if err != nil {
		var ae = new(ca.AdminClientError)
		if errors.As(err, &ae) && ae.Type == "notFound" { // TODO: use constant?
			// when a policy doesn't exist yet, create a new, empty policy and
			// send it to the CA.
			newPolicy := newPolicy()
			switch {
			case policycontext.HasAuthorityPolicyLevel(ctx):
				policy, err = client.CreateAuthorityPolicy(newPolicy)
			case policycontext.HasProvisionerPolicyLevel(ctx):
				policy, err = client.CreateProvisionerPolicy(provisioner, newPolicy)
			case policycontext.HasACMEPolicyLevel(ctx):
				policy, err = client.CreateACMEPolicy(provisioner, reference, keyID, newPolicy)
			default:
				panic("no context for policy creation set")
			}
			if err != nil {
				return nil, fmt.Errorf("error creating policy: %w", err)
			}
		} else {
			return nil, fmt.Errorf("error retrieving policy: %w", err)
		}
	}

	// ensure all policy properties are set
	policy = initPolicy(policy)

	return policy, nil
}

func remove(item string, items []string) []string {
	newSlice := []string{}
	for _, i := range items {
		if i != item {
			newSlice = append(newSlice, i)
		}
	}
	return newSlice
}

func newPolicy() *linkedca.Policy {
	return initPolicy(nil)
}

func initPolicy(p *linkedca.Policy) *linkedca.Policy {
	if p == nil {
		p = &linkedca.Policy{}
	}
	if p.X509 == nil {
		p.X509 = &linkedca.X509Policy{}
		p.X509.AllowWildcardLiteral = false
		p.X509.DisableSubjectCommonNameVerification = false
	}
	if p.X509.Allow == nil {
		p.X509.Allow = &linkedca.X509Names{}
	}
	if p.X509.Deny == nil {
		p.X509.Deny = &linkedca.X509Names{}
	}
	if p.Ssh == nil {
		p.Ssh = &linkedca.SSHPolicy{}
	}
	if p.Ssh.Host == nil {
		p.Ssh.Host = &linkedca.SSHHostPolicy{}
	}
	if p.Ssh.Host.Allow == nil {
		p.Ssh.Host.Allow = &linkedca.SSHHostNames{}
	}
	if p.Ssh.Host.Deny == nil {
		p.Ssh.Host.Deny = &linkedca.SSHHostNames{}
	}
	if p.Ssh.User == nil {
		p.Ssh.User = &linkedca.SSHUserPolicy{}
	}
	if p.Ssh.User.Allow == nil {
		p.Ssh.User.Allow = &linkedca.SSHUserNames{}
	}
	if p.Ssh.User.Deny == nil {
		p.Ssh.User.Deny = &linkedca.SSHUserNames{}
	}
	return p
}

func updatePolicy(ctx context.Context, client *ca.AdminClient, policy *linkedca.Policy) (*linkedca.Policy, error) {

	clictx := command.CLIContextFromContext(ctx)
	provisioner := clictx.String("provisioner")
	reference := clictx.String("reference")
	keyID := clictx.String("key-id")

	var (
		updatedPolicy *linkedca.Policy
		err           error
	)

	switch {
	case policycontext.HasAuthorityPolicyLevel(ctx):
		updatedPolicy, err = client.UpdateAuthorityPolicy(policy)
	case policycontext.HasProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		updatedPolicy, err = client.UpdateProvisionerPolicy(provisioner, policy)
	case policycontext.HasACMEPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return nil, errs.RequiredOrFlag(clictx, "reference", "key-id")
		}
		updatedPolicy, err = client.UpdateACMEPolicy(provisioner, reference, keyID, policy)
	default:
		panic("no context for policy update set")
	}

	if err != nil {
		return nil, err
	}

	return updatedPolicy, nil
}

func prettyPrint(policy *linkedca.Policy) {
	b, err := json.MarshalIndent(policy, "", "   ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
