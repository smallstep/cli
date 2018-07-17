package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

type hashConstructor func() hash.Hash

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "hash",
		Usage:     "generates and checks hashes of files and directories",
		UsageText: "step crypto hash <SUBCOMMAND> [SUBCOMMAND_FLAGS]",
		Subcommands: cli.Commands{
			digestCommand(),
			compareCommand(),
		},
	}
}

func digestCommand() cli.Command {
	return cli.Command{
		Name:      "digest",
		Action:    cli.ActionFunc(digestAction),
		Usage:     "generate a hash digest of a file or directory",
		UsageText: "step crypto hash digest FILE_OR_DIRECTORY [--alg ALGORITHM]",
		Description: `The 'step crypto hash digest' command generates a hash digest for a given
file or directory. For a file, the output is the same as tools like 'shasum'.
For directories, the tool computes a hash tree and outputs a single hash
digest.

POSITIONAL ARGUMENTS

  FILE_OR_DIRECTORY
    The path to a file or directory to hash.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "alg",
				Value: "sha256",
				Usage: `The hash algorithm to use.

  ALGORITHM must be one of:
    sha1
    sha224
    sha256 (default)
    sha384
    sha512
    sha512-224
    sha512-256
    sha
    md5 (requires '--insecure')`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
		},
	}
}

func compareCommand() cli.Command {
	return cli.Command{
		Name:      "compare",
		Action:    cli.ActionFunc(compareAction),
		Usage:     "verify the hash digest for a file or directory matches an expected value",
		UsageText: "step crypto hash compare HASH FILE_OR_DIRECTORY [--alg ALGORITHM]",
		Description: `The 'step crypto hash compare' command verifies that the expected hash value
matches the computed hash value for a file or directory.

POSITIONAL ARGUMENTS

  HASH
    The expected hash digest

  FILE_OR_DIRECTORY
    The path to a file or directory to hash.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "alg",
				Value: "sha256",
				Usage: `The hash algorithm to use.

  ALGORITHM must be one of:
    sha1
    sha224
    sha256 (default)
    sha384
    sha512
    sha512-224
    sha512-256
    sha
    md5 (requires '--insecure')`,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
		},
	}
}

func digestAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	hc, err := getHash(ctx, ctx.String("alg"), ctx.Bool("insecure"))
	if err != nil {
		return err
	}

	filename := ctx.Args().Get(0)
	st, err := os.Stat(filename)
	if err != nil {
		return errs.FileError(err, filename)
	}

	var sum []byte
	if st.IsDir() {
		sum, err = hashDir(hc, filename)
	} else {
		sum, err = hashFile(hc(), filename)
	}
	if err != nil {
		return err
	}

	fmt.Printf("%x  %s\n", sum, filename)

	return err
}

func compareAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	hc, err := getHash(ctx, ctx.String("alg"), ctx.Bool("insecure"))
	if err != nil {
		return err
	}

	hashStr := ctx.Args().Get(0)
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return errs.Wrap(err, "error decoding %s", hashStr)
	}

	filename := ctx.Args().Get(1)
	st, err := os.Stat(filename)
	if err != nil {
		return errs.FileError(err, filename)
	}

	var sum []byte
	if st.IsDir() {
		sum, err = hashDir(hc, filename)
	} else {
		sum, err = hashFile(hc(), filename)
	}
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(sum, hashBytes) == 1 {
		fmt.Println("ok")
		return nil
	}

	return errors.New("fail")
}

// getHash returns a new hash constructor for the given algorithm. MD5
// algorithm can only be used if the insecure flag is passed.
func getHash(ctx *cli.Context, alg string, insecure bool) (hashConstructor, error) {
	switch strings.ToLower(alg) {
	case "sha", "sha1":
		return func() hash.Hash { return sha1.New() }, nil
	case "sha224":
		return func() hash.Hash { return sha256.New224() }, nil
	case "sha256":
		return func() hash.Hash { return sha256.New() }, nil
	case "sha384":
		return func() hash.Hash { return sha512.New384() }, nil
	case "sha512":
		return func() hash.Hash { return sha512.New() }, nil
	case "sha512-224":
		return func() hash.Hash { return sha512.New512_224() }, nil
	case "sha512-256":
		return func() hash.Hash { return sha512.New512_256() }, nil
	case "md5":
		if insecure {
			return func() hash.Hash { return md5.New() }, nil
		}
		return nil, errs.FlagValueInsecure(ctx, "alg", alg)
	default:
		return nil, errs.InvalidFlagValue(ctx, "alg", alg, "")
	}
}

// hashFile returns the hash of the given file using the given hash function.
func hashFile(h hash.Hash, filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}

	if _, err := io.Copy(h, f); err != nil {
		return nil, errs.FileError(err, filename)
	}

	return h.Sum(nil), nil
}

// hashDir creates a hash of a directory adding the following data to the
// hash:
//   1. Add directory mode bits to the hash
//   2. For each file/directory in directory:
//     2.1 If file: add file mode bits and sum
//     2.2 If directory: do hashDir and add sum
//   3. return sum
func hashDir(hc hashConstructor, dirname string) ([]byte, error) {
	// ReadDir returns the entries sorted by filename
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, errs.FileError(err, dirname)
	}
	st, err := os.Stat(dirname)
	if err != nil {
		return nil, errs.FileError(err, dirname)
	}

	var sum []byte
	mode := make([]byte, 4)

	// calculate sum of contents and mode
	h := hc()
	binary.LittleEndian.PutUint32(mode, uint32(st.Mode()))
	h.Write(mode)
	for _, fi := range files {
		if fi.IsDir() {
			sum, err = hashDir(hc, path.Join(dirname, fi.Name()))
			if err != nil {
				return nil, err
			}
		} else {
			binary.LittleEndian.PutUint32(mode, uint32(fi.Mode()))
			h.Write(mode)
			sum, err = hashFile(hc(), path.Join(dirname, fi.Name()))
			if err != nil {
				return nil, err
			}
		}
		h.Write(sum)
	}

	return h.Sum(nil), nil
}
