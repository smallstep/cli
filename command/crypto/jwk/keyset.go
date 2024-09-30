package jwk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/utils/sysutils"
)

func keysetCommand() cli.Command {
	return cli.Command{
		Name:      "keyset",
		Usage:     "add, remove, and find JWKs in JWK Sets",
		UsageText: "**step crypto jwk keyset** <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto jwk set** command group provides facilities for managing and
inspecting JWK Sets. A is a JSON object that represents a set of JWKs. They
are defined in RFC7517.

A JWK Set is simply a JSON object with a "keys" member whose value is an array
of JWKs. Additional members are allowed in the object. They will be preserved
by this tool, but otherwise ignored. Duplicate member names are not allowed.

For examples, see **step help crypto jwk**.`,
		Subcommands: cli.Commands{
			keysetAddCommand(),
			keysetRemoveCommand(),
			keysetListCommand(),
			keysetFindCommand(),
		},
	}
}

func keysetAddCommand() cli.Command {
	return cli.Command{
		Name:      "add",
		Action:    cli.ActionFunc(keysetAddAction),
		Usage:     "a JWK to a JWK Set",
		UsageText: "**step crypto jwk keyset add** <jwks-file>",
		Description: `**step crypto jwk keyset add** reads a JWK from STDIN and adds it to the JWK
Set in <jwks-file>. Modifications to <jwks-file> are in-place. The file is
'flock'd while it's being read and modified.

## POSITIONAL ARGUMENTS

<jwks-file>
: File containing a JWK Set`,
	}
}

func keysetRemoveCommand() cli.Command {
	return cli.Command{
		Name:      "remove",
		Action:    cli.ActionFunc(keysetRemoveAction),
		Usage:     "a JWK from a JWK Set",
		UsageText: "**step crypto jwk keyset remove** <jwks-file> [**--kid**=<kid>]",
		Description: `**step crypto jwk keyset remove** removes the JWK with a key ID matching <kid>
from the JWK Set stored in <jwks-file>. Modifications to <jwks-file> are
in-place. The file is 'flock'd while it's being read and modified.

## POSITIONAL ARGUMENTS

<jwks-file>
: File containing a JWK Set`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "kid",
				Usage: `The key ID of the JWK to remove from the JWK Set. <kid> is a case-sensitive
string.`,
			},
		},
	}
}

func keysetListCommand() cli.Command {
	return cli.Command{
		Name:      "list",
		Action:    cli.ActionFunc(keysetListAction),
		Usage:     "key IDs of JWKs in a JWK Set",
		UsageText: "**step crypto jwk keyset list** <jwks-file>",
		Description: `**step crypto jwk keyset list** lists the IDs ("kid" parameters) of JWKs in a
JWK Set.

## POSITIONAL ARGUMENTS

<jwks-file>
: File containing a JWK Set`,
	}
}

func keysetFindCommand() cli.Command {
	return cli.Command{
		Name:      "find",
		Action:    cli.ActionFunc(keysetFindAction),
		Usage:     "a JWK in a JWK Set",
		UsageText: "**step crypto jwk keyset find** <jwks-file> [**--kid**=<kid>]",
		Description: `**step crypto jwk keyset find** command locates the JWK with a key ID matching
<kid> from the JWK Set stored in <jwks-file>. The matching JWK is printed to
STDOUT.

## POSITIONAL ARGUMENTS

<jwks-file>
: File containing a JWK Set`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "kid",
				Usage: `The key ID of the JWK to locate from the JWK Set. <kid> is a case-sensitive
string.`,
			},
		},
	}
}

func keysetAddAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "error reading STDIN")
	}

	// Attempt to parse an encrypted file
	if b, err = jose.Decrypt(b, jose.WithPasswordPrompter("Please enter the password to decrypt JWK", func(s string) ([]byte, error) {
		return ui.PromptPassword(s)
	})); err != nil {
		return err
	}

	// Unmarshal the plain (or decrypted JWK)
	var jwk jose.JSONWebKey
	if err = json.Unmarshal(b, &jwk); err != nil {
		return errors.New("error reading JWK: unsupported format")
	}

	jwksFile := ctx.Args().Get(0)
	jwks, writeFunc, err := rwLockKeySet(jwksFile)
	if err != nil {
		return err
	}

	// According to RFC7517 there are cases where multiple keys can share the
	// same "kid". One example is if they have different "kty" values but are
	// considered to be equivalent alternatives by the application using them.
	jwks.Keys = append(jwks.Keys, jwk)
	return writeFunc(true)
}

func keysetRemoveAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	kid := ctx.String("kid")

	jwksFile := ctx.Args().Get(0)
	jwks, writeFunc, err := rwLockKeySet(jwksFile)
	if err != nil {
		return err
	}

	// Filtering without allocating
	keys := jwks.Keys[:0]
	for _, key := range jwks.Keys {
		if key.KeyID != kid {
			keys = append(keys, key)
		}
	}
	jwks.Keys = keys
	return writeFunc(true)
}

func keysetListAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	jwksFile := ctx.Args().Get(0)
	jwks, writeFunc, err := rwLockKeySet(jwksFile)
	if err != nil {
		return err
	}

	for _, key := range jwks.Keys {
		fmt.Println(key.KeyID)
	}

	return writeFunc(false)
}

func keysetFindAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	kid := ctx.String("kid")

	jwksFile := ctx.Args().Get(0)
	jwks, writeFunc, err := rwLockKeySet(jwksFile)
	if err != nil {
		return err
	}

	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			b, err := json.MarshalIndent(key, "", "  ")
			if err != nil {
				return errors.Wrap(err, "error marshaling JWK")
			}
			fmt.Println(string(b))
		}
	}

	return writeFunc(false)
}

func rwLockKeySet(filename string) (jwks *jose.JSONWebKeySet, writeFunc func(bool) error, err error) {
	var f *os.File

	f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		err = errs.FileError(err, filename)
		return
	}

	fd := int(f.Fd())

	// non-blocking exclusive lock
	err = sysutils.FileLock(fd)
	switch {
	case err == nil: // continue
	case errors.Is(err, syscall.EWOULDBLOCK):
		f.Close()
		err = errors.Errorf("error reading %s: file is locked", filename)
		return
	default:
		f.Close()
		err = errors.Wrapf(err, "error locking %s", filename)
		return
	}

	// close and unlock file on errors
	defer func() {
		if err != nil {
			sysutils.FileUnlock(fd)
			f.Close()
		}
	}()

	// Read key set
	var b []byte
	b, err = io.ReadAll(f)
	if err != nil {
		err = errors.Wrapf(err, "error reading %s", filename)
		return
	}

	// Unmarshal the plain JWKSet
	jwks = new(jose.JSONWebKeySet)
	if len(b) > 0 {
		if err = json.Unmarshal(b, jwks); err != nil {
			err = errors.Wrapf(err, "error reading %s", filename)
			return
		}
	}

	writeFunc = func(write bool) (err error) {
		if write {
			if b, err1 := json.MarshalIndent(jwks, "", "  "); err1 != nil {
				err = errors.Wrapf(err1, "error marshaling %s", filename)
			} else {
				if err1 := f.Truncate(0); err1 != nil {
					err = errors.Wrapf(err1, "error writing %s", filename)
				} else {
					n, err1 := f.WriteAt(b, 0)
					switch {
					case err1 != nil:
						err = errors.Wrapf(err1, "error writing %s", filename)
					case n < len(b):
						err = errors.Wrapf(io.ErrShortWrite, "error writing %s", filename)
					}
				}
			}
		}

		if err1 := sysutils.FileUnlock(fd); err1 != nil {
			err = errors.Wrapf(err1, "error unlocking %s", filename)
		}

		if err1 := f.Close(); err1 != nil {
			err = errors.Wrapf(err1, "error closing %s", filename)
		}

		return err
	}

	return
}
