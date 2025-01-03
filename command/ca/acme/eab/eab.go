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
	id          string
	provisioner string
	reference   string
	key         string
	createdAt   string
	boundAt     string
	account     string
}

func toCLI(_ *cli.Context, _ *ca.AdminClient, eak *linkedca.EABKey) *cliEAK {
	boundAt := ""
	if !eak.BoundAt.AsTime().IsZero() {
		boundAt = eak.BoundAt.AsTime().Format("2006-01-02 15:04:05 -07:00")
	}
	return &cliEAK{
		id:          eak.Id,
		provisioner: eak.Provisioner,
		reference:   eak.Reference,
		key:         base64.RawURLEncoding.Strict().EncodeToString(eak.HmacKey),
		createdAt:   eak.CreatedAt.AsTime().Format("2006-01-02 15:04:05 -07:00"),
		boundAt:     boundAt,
		account:     eak.Account,
	}
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
