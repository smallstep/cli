package hash

import (
	//nolint:gosec // md5 can only be used with --insecure flag
	"crypto/md5"
	//nolint:gosec // sha1 is being used to calculate a hash, not a key
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"

	"github.com/smallstep/cli/flags"
)

type hashConstructor func() hash.Hash

// Command returns the jwk subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "hash",
		Usage:     "generate and check hashes of files and directories",
		UsageText: "step crypto hash <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Description: `**step crypto hash** command group provides facilities for generating and
checking hashes of files and directories.

## EXAMPLES

SHA-256 digest and compare of a file:
'''
$ step crypto hash digest foo.crt
1d14bfeab8532f0fca6220f6a870d069496798e92520c4437e13b9921a3cb7f3  foo.crt

$ step crypto hash compare 1d14bfeab8532f0fca6220f6a870d069496798e92520c4437e13b9921a3cb7f3 foo.crt
ok
'''

SHA-1 digest and compare of a directory:
'''
$ step crypto hash digest --alg sha1 config/
d419284e29382983683c294f9593183f7e00961b  config/

$ step crypto hash compare --alg sha1 d419284e29382983683c294f9593183f7e00961b config
ok
'''

MD5 of a file:
'''
$ step crypto hash digest --alg md5 --insecure foo.crt
a2c5dae8eae7d116019f0478e8b0a35a  foo.crt
'''

SHA-512/256 of a list of files:
'''
$ find . -type f | xargs step crypto hash digest --alg sha512-256
'''

Compare a previously created checksum file:
'''
$ find path -type f | xargs step crypto hash digest --alg sha512-256 \> checksums.txt

$ cat checksums.txt | xargs -n 2 step crypto hash compare --alg sha512-256
'''`,
		Subcommands: cli.Commands{
			digestCommand(),
			compareCommand(),
		},
	}
}

func digestCommand() cli.Command {
	return cli.Command{
		Name:   "digest",
		Action: cli.ActionFunc(digestAction),
		Usage:  "generate a hash digest of a file or directory",
		UsageText: `**step crypto hash digest** <file-or-directory>...
[**--alg**=<algorithm>]`,
		Description: `**step crypto hash digest** generates a hash digest for a given file or
directory. For a file, the output is the same as tools like 'shasum'. For
directories, the tool computes a hash tree and outputs a single hash digest.

For examples, see **step help crypto hash**.

## POSITIONAL ARGUMENTS

<file-or-directory>
: The path to a file or directory to hash.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "alg",
				Value: "sha256",
				Usage: `The hash algorithm to use.

: <algorithm> must be one of:

		**sha1** (or sha)
		:  SHA-1 produces a 160-bit hash value

		**sha224**
		:  SHA-224 produces a 224-bit hash value

		**sha256** (default)
		:  SHA-256 produces a 256-bit hash value

		**sha384**
		:  SHA-384 produces a 384-bit hash value

		**sha512**
		:  SHA-512 produces a 512-bit hash value

		**sha512-224**
		:  SHA-512/224 uses SHA-512 and truncates the output to 224 bits

		**sha512-256**
		:  SHA-512/256 uses SHA-512 and truncates the output to 256 bits

		**md5** (requires --insecure)
		:  MD5 produces a 128-bit hash value
`,
			},
			flags.InsecureHidden,
		},
	}
}

func compareCommand() cli.Command {
	return cli.Command{
		Name:   "compare",
		Action: cli.ActionFunc(compareAction),
		Usage:  "verify the hash digest for a file or directory matches an expected value",
		UsageText: `**step crypto hash compare** <hash> <file-or-directory>
[--alg ALGORITHM]`,
		Description: `**step crypto hash compare** verifies that the expected hash value matches the
computed hash value for a file or directory.

For examples, see **step help crypto hash**.

## POSITIONAL ARGUMENTS

<hash>
: The expected hash digest

<file-or-directory>
: The path to a file or directory to hash.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "alg",
				Value: "sha256",
				Usage: `The hash algorithm to use.

: <algorithm> must be one of:

		**sha1** (or sha)
		:  SHA-1 produces a 160-bit hash value

		**sha224**
		:  SHA-224 produces a 224-bit hash value

		**sha256** (default)
		:  SHA-256 produces a 256-bit hash value

		**sha384**
		:  SHA-384 produces a 384-bit hash value

		**sha512**
		:  SHA-512 produces a 512-bit hash value

		**sha512-224**
		:  SHA-512/224 produces a 224-bit hash value

		**sha512-256**
		:  SHA-512/256 produces a 256-bit hash value

		**md5** (requires --insecure)
		:  MD5 produces a 128-bit hash value
`,
			},
			flags.InsecureHidden,
		},
	}
}

func digestAction(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return errs.TooFewArguments(ctx)
	}

	hc, err := getHash(ctx, ctx.String("alg"), ctx.Bool("insecure"))
	if err != nil {
		return err
	}

	for _, filename := range ctx.Args() {
		var st os.FileInfo
		st, err = os.Stat(filename)
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
	}

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

	// TODO: should add the filename?
	// fmt.Printf("%s: ok\n", filename)
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
		return sha1.New, nil
	case "sha224":
		return sha256.New224, nil
	case "sha256":
		return sha256.New, nil
	case "sha384":
		return sha512.New384, nil
	case "sha512":
		return sha512.New, nil
	case "sha512-224":
		return sha512.New512_224, nil
	case "sha512-256":
		return sha512.New512_256, nil
	case "md5":
		if insecure {
			return md5.New, nil
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
//  1. Add directory mode bits to the hash
//  2. For each file/directory in directory:
//     2.1 If file: add file mode bits and sum
//     2.2 If directory: do hashDir and add sum
//  3. return sum
func hashDir(hc hashConstructor, dirname string) ([]byte, error) {
	// ReadDir returns the entries sorted by filename
	dirEntries, err := os.ReadDir(dirname)
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
	for _, dirEntry := range dirEntries {
		fi, err := dirEntry.Info()
		if err != nil {
			return nil, errs.FileError(err, dirEntry.Name())
		}
		name := path.Join(dirname, fi.Name())
		switch {
		case fi.IsDir():
			sum, err = hashDir(hc, name)
		case fi.Mode()&os.ModeSymlink != 0:
			binary.LittleEndian.PutUint32(mode, uint32(fi.Mode()))
			h.Write(mode)
			sum, err = hashSymlink(hc, name)
		default:
			binary.LittleEndian.PutUint32(mode, uint32(fi.Mode()))
			h.Write(mode)
			sum, err = hashFile(hc(), name)
		}
		if err != nil {
			return nil, err
		}
		h.Write(sum)
	}

	return h.Sum(nil), nil
}

func hashSymlink(hc hashConstructor, symname string) ([]byte, error) {
	fullname, err := os.Readlink(symname)
	if err != nil {
		return nil, errs.FileError(err, symname)
	}
	if !path.IsAbs(fullname) {
		fullname = path.Join(path.Dir(symname), fullname)
	}

	// Fails if the link points to a file that does not exist.
	// TODO: Should we ignore it?
	st, err := os.Stat(fullname)
	if err != nil {
		return nil, errs.FileError(err, fullname)
	}
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return hashSymlink(hc, fullname)
	case st.IsDir():
		return hashDir(hc, fullname)
	default:
		return hashFile(hc(), fullname)
	}
}
