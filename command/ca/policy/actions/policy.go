package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/linkedca"

	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/internal/command"
)

func retrieveAndUnsetProvisionerFlagIfRequired(ctx context.Context) string {
	// when managing policies on the authority level there's no need
	// to select a provisioner, so the flag does not need to be unset.
	if policycontext.IsAuthorityPolicyLevel(ctx) {
		return ""
	}

	clictx := command.CLIContextFromContext(ctx)
	provisioner := clictx.String("provisioner")

	// unset the provisioner and issuer flag values, so that they're not used
	// automatically in token flows.
	if err := clictx.Set("provisioner", ""); err != nil {
		panic(fmt.Errorf("failed unsetting provisioner flag: %w", err))
	}
	if err := clictx.Set("issuer", ""); err != nil {
		panic(fmt.Errorf("failed unsetting issuer flag: %w", err))
	}

	return provisioner
}

func retrieveAndInitializePolicy(ctx context.Context, client *ca.AdminClient, provisioner string) (*linkedca.Policy, error) {
	var (
		clictx    = command.CLIContextFromContext(ctx)
		reference = clictx.String("eab-key-reference")
		keyID     = clictx.String("eab-key-id")
		policy    *linkedca.Policy
		err       error
	)

	switch {
	case policycontext.IsAuthorityPolicyLevel(ctx):
		policy, err = client.GetAuthorityPolicy()
	case policycontext.IsProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		policy, err = client.GetProvisionerPolicy(provisioner)
	case policycontext.IsACMEPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return nil, errs.RequiredOrFlag(clictx, "eab-key-reference", "eab-key-id")
		}
		policy, err = client.GetACMEPolicy(provisioner, reference, keyID)
	default:
		panic("no context for policy retrieval set")
	}

	if err != nil {
		var ae *ca.AdminClientError
		if errors.As(err, &ae) && ae.Type == "notFound" { // TODO: use constant?
			// when a policy doesn't exist yet, create a new, empty policy and
			// send it to the CA.
			newPolicy := newPolicy()
			switch {
			case policycontext.IsAuthorityPolicyLevel(ctx):
				policy, err = client.CreateAuthorityPolicy(newPolicy)
			case policycontext.IsProvisionerPolicyLevel(ctx):
				policy, err = client.CreateProvisionerPolicy(provisioner, newPolicy)
			case policycontext.IsACMEPolicyLevel(ctx):
				policy, err = client.CreateACMEPolicy(provisioner, reference, keyID, newPolicy)
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
	var i int
	for _, v := range items {
		if item != v {
			items[i] = v
			i++
		}
	}
	return items[:i]
}

func newPolicy() *linkedca.Policy {
	return initPolicy(nil)
}

// addOrRemoveArguments adds or removes args to/from existingNames
func addOrRemoveArguments(existingNames, args []string, shouldRemove bool) []string {
	if shouldRemove {
		for _, name := range args {
			existingNames = remove(name, existingNames)
		}
	} else {
		existingNames = append(existingNames, args...)
	}
	return existingNames
}

func initPolicy(p *linkedca.Policy) *linkedca.Policy {
	if p == nil {
		p = &linkedca.Policy{}
	}
	if p.X509 == nil {
		p.X509 = &linkedca.X509Policy{}
		p.X509.AllowWildcardNames = false
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

func updatePolicy(ctx context.Context, client *ca.AdminClient, policy *linkedca.Policy, provisioner string) (*linkedca.Policy, error) {
	var (
		clictx        = command.CLIContextFromContext(ctx)
		reference     = clictx.String("eab-key-reference")
		keyID         = clictx.String("eab-key-id")
		updatedPolicy *linkedca.Policy
		err           error
	)

	// deduplicate values before sending them
	policy.Deduplicate()

	switch {
	case policycontext.IsAuthorityPolicyLevel(ctx):
		updatedPolicy, err = client.UpdateAuthorityPolicy(policy)
	case policycontext.IsProvisionerPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		updatedPolicy, err = client.UpdateProvisionerPolicy(provisioner, policy)
	case policycontext.IsACMEPolicyLevel(ctx):
		if provisioner == "" {
			return nil, errs.RequiredFlag(clictx, "provisioner")
		}
		if reference == "" && keyID == "" {
			return nil, errs.RequiredOrFlag(clictx, "eab-key-reference", "eab-key-id")
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

func prettyPrint(policy *linkedca.Policy) error {
	b, err := protojson.Marshal(policy)
	if err != nil {
		return fmt.Errorf("error marshaling policy: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "   "); err != nil {
		return fmt.Errorf("error indenting policy JSON representation: %w", err)
	}

	fmt.Println(buf.String())

	return nil
}
