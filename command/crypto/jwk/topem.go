package jwk

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/utils"
)

func toPEMCommand() cli.Command {
	return cli.Command{
		Name:      "to-pem",
		Action:    cli.ActionFunc(toPEMAction),
		Usage:     "Extract key from JWK and write to disk as PEM",
		UsageText: `**step crypto jwk to-pem** <key> <pem>`,
		Description: `**step crypto jwk to-pem** extracts a key from a JWK
(encrypted or plaintext) and writes the key to disk in PEM format.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt the private key.
Sensitive key material will be written to disk unencrypted. This is not
recommended. Requires **--insecure** flag.`,
			},
		},
	}
}

// toPEMAction extracts the public or private key from a JWK and writes the key
// key to disk in PEM format.
func toPEMAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}
	jwkPath := ctx.Args().Get(0)
	pemPath := ctx.Args().Get(1)

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "insecure", "no-password")
	}

	jwk, err := jose.ParseKey(jwkPath)
	if err != nil {
		return err
	}

	if jwk.IsPublic() {
		if _, err := pemutil.Serialize(jwk.Key, pemutil.ToFile(pemPath, 0644)); err != nil {
			return err
		}
	} else {
		if noPass {
			if _, err := pemutil.Serialize(jwk.Key, pemutil.ToFile(pemPath, 0644)); err != nil {
				return err
			}
		} else {
			pass, err := utils.ReadPassword(fmt.Sprintf("Please enter the password to encrypt %s: ", pemPath))
			if err != nil {
				return errors.Wrap(err, "error reading password")
			}

			if _, err := pemutil.Serialize(jwk.Key, pemutil.WithEncryption(pass),
				pemutil.ToFile(pemPath, 0644)); err != nil {
				return err
			}
		}
	}

	return nil
}
