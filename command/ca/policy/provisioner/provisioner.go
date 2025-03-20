package provisioner

import (
	"context"

	"github.com/urfave/cli"

	"github.com/smallstep/cli/command/ca/policy/actions"
	"github.com/smallstep/cli/command/ca/policy/policycontext"
	"github.com/smallstep/cli/command/ca/policy/ssh"
	"github.com/smallstep/cli/command/ca/policy/x509"
)

// Command returns the policy subcommand.
func Command(ctx context.Context) cli.Command {
	ctx = policycontext.WithProvisionerPolicyLevel(ctx)
	return cli.Command{
		Name:      "provisioner",
		Usage:     "manage certificate issuance policies for provisioners",
		UsageText: "**step ca policy provisioner** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step ca policy provisioner** command group provides facilities for managing certificate issuance policies for provisioners.

Please note that certificate issuance policies on the provisioner level are currently only supported in Certificate Manager: https://u.step.sm/cm.		

`,
		Subcommands: cli.Commands{
			actions.ViewCommand(ctx),
			actions.RemoveCommand(ctx),
			x509.Command(ctx),
			ssh.Command(ctx),
		},
	}
}
