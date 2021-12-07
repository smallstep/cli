package jose

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
	"github.com/urfave/cli"
)

// Command returns the cli.Command for jose related subcommands.
func Command() cli.Command {
	return cli.Command{
		Name:      "jose",
		Usage:     "collection of JOSE utilities",
		UsageText: "step crypto jose <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			formatCommand(),
		},
	}
}

type serializer interface {
	CompactSerialize() (string, error)
	FullSerialize() string
}

func formatCommand() cli.Command {
	return cli.Command{
		Name:      "format",
		Usage:     "swap serialization format",
		UsageText: `**step crypto jose format**`,
		Action:    cli.ActionFunc(formatAction),
		Description: `**step crypto jose format** reads a JWT, a JWS, or a JWE from STDIN swaps the
serialization of the content, from compact to JSON or from JSON to compact.

## EXAMPLES

Transform a JSON encrypted message to the compact serialization format:
'''
$ echo The message | step crypto jwe encrypt --key p256.enc.pub | step crypto jose format
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlNTR1pNdjZyMGlHbmtsMnpKRERXS1JlaDU4R3RwTjVjT2tBZnlaaUI0enMiLCJ5IjoiLUJzQ2w5RjZNd28zRWZoTFJIeVdDbGlxU2d6T2tubzNuWW80azlPSVk0TSJ9LCJraWQiOiJHd0tSTUdXY1pWNFE2dGZZblpjZm90N090N2hjQ0t2cUJPVWljX0JoZ0gwIn0
.
.
iJNn8SrqE8I5Bhog
.
NO9FfC25Ow9ogzq1.6M3Jiy_osGwlioJjXPyl9w
'''

Transform a compact token to the JSON serialization format:
'''
$ step crypto jwt sign --key p256.priv.json --iss "joe" --aud "bob" \
      --sub "hello" --exp $(date -v+1M +"%s") | step crypto jose format
{
  "payload":"eyJhdWQiOiJib2IiLCJleHAiOjE1MzUyNDE4OTYsImlhdCI6MTUzMjU2MzQ5OCwiaXNzIjoiam9lIiwibmJmIjoxNTMyNTYzNDk4LCJzdWIiOiJoZWxsbyJ9",
  "protected":"eyJhbGciOiJFUzI1NiIsImtpZCI6IlpqR1g5N0xtY2ZsUG9sV3Zzb0FXekM1V1BXa05GRkgzUWRLTFVXOTc4aGsiLCJ0eXAiOiJKV1QifQ",
  "signature":"wlRDGrjQItHFu5j2H4A4T6_P5Ek00ugJXQ3iIXibsZjU96_BaqddnAqFWeKpb6xHWGRAHKtlm9bUYBfLQ8Jlsg"
}
'''`,
	}
}

func formatAction(ctx *cli.Context) error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return errors.Wrap(err, "error reading input")
	}

	token := stripWhitespace(string(input))

	// Attempt to parse an encrypted
	// If it fails parse a regular JWS
	var srz serializer
	if enc, err := jose.ParseEncrypted(token); err == nil {
		srz = enc
	} else {
		tok, err := jose.ParseJWS(token)
		if err != nil {
			return errors.Wrap(trimPrefix(err), "error parsing data")
		}
		srz = tok
	}

	if strings.HasPrefix(token, "{") {
		str, err := srz.CompactSerialize()
		if err != nil {
			return errors.Wrap(trimPrefix(err), "error serializing data")
		}
		fmt.Println(str)
	} else {
		fmt.Println(srz.FullSerialize())
	}

	return nil
}

func trimPrefix(err error) error {
	return errors.New(strings.TrimPrefix(err.Error(), "square/go-jose: "))
}

var stripWhitespaceRegex = regexp.MustCompile(`\s`)

// stripWhitespace strip all newlines and whitespace
func stripWhitespace(data string) string {
	return stripWhitespaceRegex.ReplaceAllString(data, "")
}
