package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/utils"
)

func changePassCommand() cli.Command {
	return cli.Command{
		Name:   "change-pass",
		Action: cli.ActionFunc(changePassAction),
		Usage:  "Change password on a an encrypted private key (PEM or JWK format)",
		UsageText: `**step crypto change-pass** <key> [**--new-key**=<file>]
[**type**=<string>]`,
		Description: `**step crypto change-pass** encrypts a private key to disk
by either overwriting the original encrypted key or writing a new file to disk.
from the configuration and writes the new configuration back to the CA config`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "new-key",
				Usage: "<file> new encrypted key path. Default to overwriting the <key> positional argument",
			},
			cli.StringFlag{
				Name: "type",
				Usage: `The <type> (key type) to encrypt.
If unset, default is PEM.

: <type> is a case-sensitive string and must be one of:

    **PEM**
    :  Decrypt and then Re-encrypt a PEM formatted key

    **JWK**
    :  Decrypt and then Re-encrypt a JWK
`,
				Value: "PEM",
			},
		},
	}
}

const (
	// 128-bit salt
	pbkdf2SaltSize = 16
	// 100k iterations. Nist recommends at least 10k, 1Passsword uses 100k.
	pbkdf2Iterations = 100000
)

// changePassAction does the following:
//   1. decrypts a private key (if necessary)
//   2. encrypts the key using a new password
//   3. writes the encrypted key to the original file
func changePassAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	keyPath := ctx.Args().Get(0)

	newKeyPath := ctx.String("new-key")
	typ := ctx.String("type")

	if len(newKeyPath) == 0 {
		newKeyPath = keyPath
	}

	switch typ {
	case "PEM":
		keyBytes, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return errs.FileError(err, keyPath)
		}
		k, err := pemutil.Parse(keyBytes, pemutil.WithFilename(keyPath))
		if err != nil {
			return err
		}

		pass, err := utils.ReadPassword(fmt.Sprintf("Please enter the password to encrypt %s: ", newKeyPath))
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}

		if _, err := pemutil.Serialize(k, pemutil.WithEncryption(pass),
			pemutil.ToFile(keyPath, 0644)); err != nil {
			return err
		}
	case "JWK":
		jwk, err := jose.ParseKey(keyPath)
		if err != nil {
			return err
		}
		var rcpt jose.Recipient
		// Generate JWE encryption key.
		if jose.SupportsPBKDF2 {
			pass, err := utils.ReadPassword(fmt.Sprintf("Please enter the password to encrypt %s: ", newKeyPath))
			if err != nil {
				return errors.Wrap(err, "error reading password")
			}

			salt, err := randutil.Salt(pbkdf2SaltSize)
			if err != nil {
				return err
			}

			rcpt = jose.Recipient{
				Algorithm:  jose.PBES2_HS256_A128KW,
				Key:        []byte(pass),
				PBES2Count: pbkdf2Iterations,
				PBES2Salt:  salt,
			}
		} else {
			pass, err := randutil.Alphanumeric(32)
			if err != nil {
				return errors.Wrap(err, "error generating password")
			}
			fmt.Printf("Private JWK file '%s' will be encrypted with the key:\n%s\n", newKeyPath, pass)
			rcpt = jose.Recipient{Algorithm: jose.A128KW, Key: []byte(pass)}
		}

		b, err := json.Marshal(jwk)
		if err != nil {
			return errors.Wrap(err, "error marshaling JWK")
		}

		encrypter, err := jose.NewEncrypter(jose.A128GCM, rcpt, nil)
		if err != nil {
			return errors.Wrap(err, "error creating cipher")
		}

		obj, err := encrypter.Encrypt(b)
		if err != nil {
			return errors.Wrap(err, "error encrypting JWK")
		}

		var out bytes.Buffer
		if err := json.Indent(&out, []byte(obj.FullSerialize()), "", "  "); err != nil {
			return errors.Wrap(err, "error formatting JSON")
		}
		b = out.Bytes()
		if err := utils.WriteFile(newKeyPath, b, 0600); err != nil {
			return errs.FileError(err, newKeyPath)
		}
	}

	return nil
}
