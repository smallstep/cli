package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func changePassCommand() cli.Command {
	return cli.Command{
		Name:   "change-pass",
		Action: command.ActionFunc(changePassAction),
		Usage:  "change password of an encrypted private key (PEM or JWK format)",
		UsageText: `**step crypto change-pass** <key-file>
[**--out**=<file>] [**--password-file**=<file>] [**--new-password-file**=<file>]
[**--insecure**] [**--no-password**]`,
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
				Name:  "password-file",
				Usage: `The path to the <file> containing the password to decrypt the private key.`,
			},
			cli.StringFlag{
				Name:  "new-password-file",
				Usage: `The path to the <file> containing the password to encrypt the private key.`,
			},
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The <file> new encrypted key path. Default to overwriting the <key> positional argument",
			},
			flags.Force,
			flags.Insecure,
			flags.NoPassword,
		},
	}
}

// changePassAction does the following:
//  1. decrypts a private key (if necessary)
//  2. encrypts the key using a new password
//  3. writes the encrypted key to the original file
func changePassAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	decryptPassFile := ctx.String("password-file")
	encryptPassFile := ctx.String("new-password-file")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "no-password", "insecure")
	}

	keyPath := ctx.Args().Get(0)
	newKeyPath := ctx.String("out")
	if newKeyPath == "" {
		newKeyPath = keyPath
	}

	b, err := os.ReadFile(keyPath)
	if err != nil {
		return errs.FileError(err, keyPath)
	}

	if bytes.HasPrefix(b, []byte("-----BEGIN ")) {
		opts := []pemutil.Options{pemutil.WithFilename(keyPath)}
		if decryptPassFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(decryptPassFile))
		}
		key, err := pemutil.Parse(b, opts...)
		if err != nil {
			return err
		}
		opts = []pemutil.Options{}
		if !noPass {
			if encryptPassFile != "" {
				opts = append(opts, pemutil.WithPasswordFile(encryptPassFile))
			} else {
				pass, err := ui.PromptPassword(fmt.Sprintf("Please enter the password to encrypt %s", newKeyPath))
				if err != nil {
					return errors.Wrap(err, "error reading password")
				}
				opts = append(opts, pemutil.WithPassword(pass))
			}
		}
		opts = append(opts, pemutil.ToFile(newKeyPath, 0644))
		if _, err := pemutil.Serialize(key, opts...); err != nil {
			return err
		}
	} else {
		opts := []jose.Option{}
		if decryptPassFile != "" {
			opts = append(opts, jose.WithPasswordFile(decryptPassFile))
		}
		jwk, err := jose.ReadKey(keyPath, opts...)
		if err != nil {
			return err
		}
		b, err := json.Marshal(jwk)
		if err != nil {
			return err
		}
		if !noPass {
			opts = []jose.Option{
				jose.WithPasswordPrompter("Please enter the password to encrypt the private JWK", func(s string) ([]byte, error) {
					return ui.PromptPassword(s)
				}),
			}
			if encryptPassFile != "" {
				opts = append(opts, jose.WithPasswordFile(encryptPassFile))
			}
			jwe, err := jose.Encrypt(b, opts...)
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
