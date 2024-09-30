package jwk

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

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
		UsageText: `**step crypto jwk thumbprint**`,
		Description: `**step crypto jwk thumbprint** reads a JWK from STDINT, derives the
corresponding JWK Thumbprint (RFC7638), and prints the base64-urlencoded
thumbprint to STDOUT.

For examples, see **step help crypto jwk**.`,
	}
}

func thumbprintAction(*cli.Context) error {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "error reading from STDIN")
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

	hash, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return errors.Wrap(err, "error generating JWK thumbprint")
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(hash))
	return nil
}
