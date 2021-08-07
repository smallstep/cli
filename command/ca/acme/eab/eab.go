package eab

import (
	"encoding/base64"

	adminAPI "github.com/smallstep/certificates/authority/admin/api"
	"github.com/smallstep/certificates/ca"
	"github.com/urfave/cli"
)

type cliEAK struct {
	id          string
	provisioner string
	name        string
	key         string
}

func toCLI(ctx *cli.Context, client *ca.AdminClient, eak *adminAPI.CreateExternalAccountKeyResponse) (*cliEAK, error) {
	// TODO: more fields for other purposes, like including the createdat/boundat/account for listing?
	return &cliEAK{id: eak.KeyID, provisioner: eak.ProvisionerName, name: eak.Name, key: base64.StdEncoding.EncodeToString(eak.Key)}, nil
}

// Command returns the eab subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "eab",
		Usage:     "create and manage ACME External Account Binding Keys",
		UsageText: "**step beta ca acme eab** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			addCommand(),
		},
		Description: `**step beta ca acme eab** command group provides facilities for managing ACME 
		External Account Binding Keys.

## EXAMPLES

List the active ACME External Account Binding Keys:
'''
$ step beta ca acme eab list
'''

Add an ACME External Account Binding Key:
'''
$ step beta ca acme eab add provisioner_name some_name_or_reference
'''`,
	}
}
