package jwk

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
)

func thumbprintCommand() cli.Command {
	return cli.Command{
		Name:      "thumbprint",
		Action:    cli.ActionFunc(thumbprintAction),
		Usage:     "compute thumbprint for a JWK",
		UsageText: `**step crypto jwk thumbprint** [<jwk-file>]`,
		Description: `**step crypto jwk thumbprint** reads a JWK from <jwk-file> or STDIN, derives
the corresponding JWK Thumbprint (RFC7638), and prints the base64-urlencoded
thumbprint to STDOUT.

## POSITIONAL ARGUMENTS

<jwk-file>
:  Path to a JWK. If it is not set, the JWK is read from STDIN.

For examples, see **step help crypto jwk**.`,
	}
}

func thumbprintAction(ctx *cli.Context) error {
	b, err := readFromStdInOrFile(ctx)
	if err != nil {
		return err
	}

	jwk := new(jose.JSONWebKey)
	// Attempt to decrypt if encrypted
	if b, err = jose.Decrypt(b, jose.WithPasswordPrompter("Please enter the password to decrypt your private JWK", func(s string) ([]byte, error) {
		return ui.PromptPassword(s)
	})); err != nil {
		return err
	}

	// Unmarshal the plain (or decrypted JWK)
	if err = json.Unmarshal(b, jwk); err != nil {
		return errors.New("error reading JWK: unsupported format")
	}

	s, err := jose.Thumbprint(jwk)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}
