package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
)

func changePassCommand() cli.Command {
	return cli.Command{
		Name:      "change-pass",
		Action:    command.ActionFunc(changePassAction),
		Usage:     "change password of an encrypted private key (PEM or JWK format)",
		UsageText: `**step crypto change-pass** <key-file> [**--out**=<file>]`,
		Description: `**step crypto change-pass** extracts the private key from
a file and encrypts disk using a new password by either overwriting the original
encrypted key or writing a new file to disk.

## POSITIONAL ARGUMENTS

<key-file>
: The PEM or JWK file with the encrypted key.

## EXAMPLES

Change password for PEM formatted key:
'''
$ step crypto change-pass key.pem
'''

Change password for PEM formatted key and write encrypted key to different file:
'''
$ step crypto change-pass key.pem --out new-key.pem
'''

Change password for JWK formatted key:
'''
$ step crypto change-pass key.jwk
'''

Change password for JWK formatted key:
'''
$ step crypto change-pass key.jwk --out new-key.jwk
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The <file> new encrypted key path. Default to overwriting the <key> positional argument",
			},
			flags.Force,
		},
	}
}

// changePassAction does the following:
//   1. decrypts a private key (if necessary)
//   2. encrypts the key using a new password
//   3. writes the encrypted key to the original file
func changePassAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	keyPath := ctx.Args().Get(0)

	newKeyPath := ctx.String("out")
	if len(newKeyPath) == 0 {
		newKeyPath = keyPath
	}

	b, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return errs.FileError(err, keyPath)
	}

	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		key, err := pemutil.Parse(b, pemutil.WithFilename(keyPath))
		if err != nil {
			return err
		}
		pass, err := ui.PromptPassword(fmt.Sprintf("Please enter the password to encrypt %s", newKeyPath))
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
		if _, err := pemutil.Serialize(key, pemutil.WithEncryption(pass), pemutil.ToFile(newKeyPath, 0644)); err != nil {
			return err
		}
	} else {
		jwk, err := jose.ParseKey(keyPath)
		if err != nil {
			return err
		}
		jwe, err := jose.EncryptJWK(jwk)
		if err != nil {
			return err
		}
		var out bytes.Buffer
		if err := json.Indent(&out, []byte(jwe.FullSerialize()), "", "  "); err != nil {
			return errors.Wrap(err, "error formatting JSON")
		}
		if err := utils.WriteFile(newKeyPath, out.Bytes(), 0600); err != nil {
			return errs.FileError(err, newKeyPath)
		}
	}

	ui.Printf("Your key has been saved in %s.\n", newKeyPath)
	return nil
}
