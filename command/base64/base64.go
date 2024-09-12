package base64

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"

	"github.com/smallstep/cli/utils"
)

func init() {
	cmd := cli.Command{
		Name:   "base64",
		Action: command.ActionFunc(base64Action),
		Usage:  "encodes and decodes using base64 representation",
		UsageText: `**step base64**
[**-d**|**--decode**] [**-r**|**--raw**] [**-u**|**--url**]`,
		Description: `**step base64** implements base64 encoding as specified by RFC 4648.

## Examples

Encode to base64 using the standard encoding:
'''
$ echo -n This is the string to encode | step base64
VGhpcyBpcyB0aGUgc3RyaW5nIHRvIGVuY29kZQ==
$ step base64 This is the string to encode
VGhpcyBpcyB0aGUgc3RyaW5nIHRvIGVuY29kZQ==
'''

Decode a base64 encoded string:
'''
$ echo VGhpcyBpcyB0aGUgc3RyaW5nIHRvIGVuY29kZQ== | step base64 -d
This is the string to encode
'''

Encode to base64 without padding:
'''
$ echo -n This is the string to encode | step base64 -r
VGhpcyBpcyB0aGUgc3RyaW5nIHRvIGVuY29kZQ
$ step base64 -r This is the string to encode
VGhpcyBpcyB0aGUgc3RyaW5nIHRvIGVuY29kZQ
'''

Encode to base64 using the url encoding:
'''
$ echo 'abc123$%^&*()_+-=~' | step base64 -u
YWJjMTIzJCVeJiooKV8rLT1-Cg==
'''

Decode an url encoded base64 string. The encoding type can be enforced
using the '-u' or '-r' flags, but it will be auto-detected if they are not
passed:
'''
$ echo YWJjMTIzJCVeJiooKV8rLT1-Cg== | step base64 -d
abc123$%^&*()_+-=~
$ echo YWJjMTIzJCVeJiooKV8rLT1-Cg== | step base64 -d -u
abc123$%^&*()_+-=~
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "d,decode",
				Usage: "decode base64 input",
			},
			cli.BoolFlag{
				Name:  "r,raw",
				Usage: "use the unpadded base64 encoding",
			},
			cli.BoolFlag{
				Name:  "u,url",
				Usage: "use the encoding format typically used in URLs and file names",
			},
		},
	}

	command.Register(cmd)
}

func base64Action(ctx *cli.Context) error {
	var err error
	var data []byte
	isDecode := ctx.Bool("decode")

	if ctx.NArg() > 0 {
		data = []byte(strings.Join(ctx.Args(), " "))
	} else {
		var prompt string
		if isDecode {
			prompt = "Please enter text to decode"
		} else {
			prompt = "Please enter text to encode"
		}

		if data, err = utils.ReadInput(prompt); err != nil {
			return err
		}
	}

	enc := getEncoder(ctx, data)
	if isDecode {
		b, err := enc.DecodeString(string(data))
		if err != nil {
			return errors.Wrap(err, "error decoding input")
		}
		os.Stdout.Write(b)
	} else {
		fmt.Println(enc.EncodeToString(data))
	}

	return nil
}

func getEncoder(ctx *cli.Context, data []byte) *base64.Encoding {
	raw := ctx.Bool("raw")
	url := ctx.Bool("url")
	isDecode := ctx.Bool("decode")

	// Detect encoding
	if isDecode && !ctx.IsSet("raw") && !ctx.IsSet("url") {
		raw = !bytes.HasSuffix(bytes.TrimSpace(data), []byte("="))
		url = bytes.Contains(data, []byte("-")) || bytes.Contains(data, []byte("_"))
	}

	if raw {
		if url {
			return base64.RawURLEncoding
		}
		return base64.RawStdEncoding
	}
	if url {
		return base64.URLEncoding
	}

	return base64.StdEncoding
}
