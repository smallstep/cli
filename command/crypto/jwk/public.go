package jwk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
)

func publicCommand() cli.Command {
	return cli.Command{
		Name:      "public",
		Action:    cli.ActionFunc(publicAction),
		Usage:     "extract a public JSON Web Key (JWK) from a private JWK",
		UsageText: `**step crypto jwk public**`,
		Description: `**step crypto jwk public** command reads a JWK from STDIN, derives the
corresponding public JWK, and prints the derived JWK to STDOUT.

For examples, see **step help crypto jwk**.`,
	}
}

func publicAction(*cli.Context) error {
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

	var public jose.JSONWebKey

	// go-jose JSONWebKey.Public() returns an empty key for oct
	if _, ok := jwk.Key.([]byte); ok {
		public = *jwk
	} else {
		public = jwk.Public()
	}

	b, err = json.MarshalIndent(public, "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling JWK")
	}

	fmt.Println(string(b))
	return nil
}
