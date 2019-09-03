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
		Name:   "change-pass",
		Action: command.ActionFunc(changePassAction),
		Usage:  "change password of an encrypted private key (PEM or JWK format)",
		UsageText: `**step crypto change-pass** <key-file>
[**--out**=<file>] [**--insecure**] [**--no-password**]`,
		Description: `**step crypto change-pass** extracts and decrypts
the private key from a file and encrypts and serializes the key to disk using a
new password.

## POSITIONAL ARGUMENTS

<key-file>
: The PEM or JWK file with the encrypted key.

## EXAMPLES

Change password for PEM formatted key:
'''
$ step crypto change-pass key.pem
'''

Remove password for PEM formatted key:
'''
$ step crypto change-pass key.pem --no-password --insecure
'''

Change password for PEM formatted key and write encrypted key to different file:
'''
$ step crypto change-pass key.pem --out new-key.pem
'''

Change password for JWK formatted key:
'''
$ step crypto change-pass key.jwk
'''

Removed password for JWK formatted key:
'''
$ step crypto change-pass key.jwk --no-password --insecure
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
			flags.Insecure,
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt the private key.
Sensitive key material will be written to disk unencrypted. This is not
recommended. Requires **--insecure** flag.`,
			},
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

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "insecure", "no-password")
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
		var opts []pemutil.Options
		if !noPass {
			pass, err := ui.PromptPassword(fmt.Sprintf("Please enter the password to encrypt %s", newKeyPath))
			if err != nil {
				return errors.Wrap(err, "error reading password")
			}
			opts = append(opts, pemutil.WithPassword(pass))
		}
		opts = append(opts, pemutil.ToFile(newKeyPath, 0644))
		if _, err := pemutil.Serialize(key, opts...); err != nil {
			return err
		}
	} else {
		jwk, err := jose.ParseKey(keyPath)
		if err != nil {
			return err
		}
		var b []byte
		if noPass {
			b, err = jwk.MarshalJSON()
			if err != nil {
				return err
			}
		} else {
			jwe, err := jose.EncryptJWK(jwk)
			if err != nil {
				return err
			}
			b = []byte(jwe.FullSerialize())
		}
		var out bytes.Buffer
		if err := json.Indent(&out, b, "", "  "); err != nil {
			return errors.Wrap(err, "error formatting JSON")
		}
		if err := utils.WriteFile(newKeyPath, out.Bytes(), 0600); err != nil {
			return errs.FileError(err, newKeyPath)
		}
	}

	ui.Printf("Your key has been saved in %s.\n", newKeyPath)
	return nil
}
