package eab

import (
	"encoding/base64"
	"fmt"
	"html"
	"strconv"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/ca"
)

type cliEAK struct {
	ID          string `json:"id"`
	Provisioner string `json:"provisioner"`
	Reference   string `json:"reference"`
	Key         string `json:"key,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
	BoundAt     string `json:"boundAt,omitempty"`
	Account     string `json:"account,omitempty"`
}

func toCLI(_ *cli.Context, _ *ca.AdminClient, eak *linkedca.EABKey) *cliEAK {
	createdAt := ""
	if !eak.CreatedAt.AsTime().IsZero() {
		createdAt = eak.CreatedAt.AsTime().Format("2006-01-02 15:04:05 -07:00")
	}
	boundAt := ""
	if !eak.BoundAt.AsTime().IsZero() {
		boundAt = eak.BoundAt.AsTime().Format("2006-01-02 15:04:05 -07:00")
	}
	return &cliEAK{
		ID:          eak.Id,
		Provisioner: eak.Provisioner,
		Reference:   eak.Reference,
		Key:         base64.RawURLEncoding.Strict().EncodeToString(eak.HmacKey),
		CreatedAt:   createdAt,
		BoundAt:     boundAt,
		Account:     eak.Account,
	}
}

// jsonFlag toggles machine-readable JSON output for the eab subcommands.
var jsonFlag = cli.BoolFlag{
	Name:  "json",
	Usage: `Print output as a JSON object (or array) instead of the human-readable table.`,
}

// Command returns the eab subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "eab",
		Usage:     "create and manage ACME External Account Binding Keys",
		UsageText: "**step ca acme eab** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			listCommand(),
			addCommand(),
			removeCommand(),
		},
		Description: `**step ca acme eab** command group provides facilities for managing ACME
		External Account Binding Keys.

## EXAMPLES

List the active ACME External Account Binding Keys:
'''
$ step ca acme eab list my_provisioner
'''

Add an ACME External Account Binding Key:
'''
$ step ca acme eab add my_provisioner my_reference
'''

Remove an ACME External Account Binding Key:
'''
$ step ca acme eab remove my_provisioner my_key_id
'''
`,
	}
}

// notImplemented checks if an error indicates that the operation is not implemented
// in the CA and adds additional information to the error if that's the case. Other
// types of errors pass through without changes.
func notImplemented(err error) error {
	var adminErr *ca.AdminClientError
	if errors.As(err, &adminErr) && adminErr.Type == admin.ErrorNotImplementedType.String() {
		emoji := html.UnescapeString("&#"+strconv.Itoa(128640)+";") + " " +
			html.UnescapeString("&#"+strconv.Itoa(129321)+";")
		return fmt.Errorf("this functionality is currently only available in Certificate Manager: https://u.step.sm/cm %s", emoji)
	}
	return err
}
