package actions

import (
	"context"
	"fmt"

	"github.com/smallstep/cli/internal/command"
	"github.com/smallstep/cli/utils/cautils"
)

// AllowWildcardsAction updates the policy to allow wildcard names.
func AllowWildcardsAction(ctx context.Context) (err error) {
	clictx := command.CLIContextFromContext(ctx)

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return fmt.Errorf("error retrieving policy: %w", err)
	}

	policy.X509.AllowWildcardNames = true

	updatedPolicy, err := updatePolicy(ctx, client, policy)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	return prettyPrint(updatedPolicy)
}

// DenyWildcardsAction updates the policy to deny wildcard names.
func DenyWildcardsAction(ctx context.Context) (err error) {
	clictx := command.CLIContextFromContext(ctx)

	client, err := cautils.NewAdminClient(clictx)
	if err != nil {
		return fmt.Errorf("error creating admin client: %w", err)
	}

	policy, err := retrieveAndInitializePolicy(ctx, client)
	if err != nil {
		return fmt.Errorf("error retrieving policy: %w", err)
	}

	policy.X509.AllowWildcardNames = false

	updatedPolicy, err := updatePolicy(ctx, client, policy)
	if err != nil {
		return fmt.Errorf("error updating policy: %w", err)
	}

	return prettyPrint(updatedPolicy)
}
