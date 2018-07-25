package jose

import (
	"fmt"
	"io/ioutil"
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
serialization of the content, from compact to JSON or from JSON to compact.`,
	}
}

func formatAction(ctx *cli.Context) error {
	input, err := ioutil.ReadAll(os.Stdin)
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

var stripWhitespaceRegex = regexp.MustCompile("\\s")

// stripWhitespace strip all newlines and whitespace
func stripWhitespace(data string) string {
	return stripWhitespaceRegex.ReplaceAllString(data, "")
}
