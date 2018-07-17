package jwk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/smallstep/cli/command/crypto/internal/jose"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

func publicCommand() cli.Command {
	return cli.Command{
		Name:      "public",
		Action:    cli.ActionFunc(publicAction),
		Usage:     "extract a public JSON Web Key (JWK) from a private JWK",
		UsageText: `step crypto jwk public`,
		Description: `The 'step crypto jwk public' command reads a JWK from STDIN, derives
the corresponding public JWK, and prints the derived JWK to STDOUT.`,
	}
}

func publicAction(ctx *cli.Context) error {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "error reading from STDIN")
	}

	jwk := new(jose.JSONWebKey)
	// Attempt to decrypt if encrypted
	if b, err = jose.Decrypt("Please enter the password to decrypt your private JWK: ", b); err != nil {
		return err
	}

	// Unmarshal the plain (or decrypted JWK)
	if err := json.Unmarshal(b, jwk); err != nil {
		return errors.New("error reading JWK: unsupported format")
	}

	b, err = json.MarshalIndent(jwk.Public(), "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling JWK")
	}

	fmt.Println(string(b))
	return nil
}
