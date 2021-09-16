package eab

import (
	"encoding/base64"
	"time"

	"github.com/smallstep/certificates/ca"
	"github.com/urfave/cli"
	"go.step.sm/linkedca"
)

type cliEAK struct {
	id          string
	provisioner string
	name        string
	key         string
	createdAt   time.Time
	boundAt     string
	account     string
}

func toCLI(ctx *cli.Context, client *ca.AdminClient, eak *linkedca.EABKey) (*cliEAK, error) {
	boundAt := ""
	if !eak.BoundAt.AsTime().IsZero() {
		boundAt = eak.BoundAt.AsTime().Format("2006-01-02 15:04:05 -07:00")
	}
	return &cliEAK{
		id:          eak.Id,
		provisioner: eak.ProvisionerName,
		name:        eak.Name,
		key:         base64.RawURLEncoding.Strict().EncodeToString(eak.HmacKey),
		createdAt:   eak.CreatedAt.AsTime(),
		boundAt:     boundAt,
		account:     eak.Account,
	}, nil
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
			removeCommand(),
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
'''

Remove an ACME External Account Binding Key:
'''
$ step beta ca acme eab remove key_id
'''
`,
	}
}
