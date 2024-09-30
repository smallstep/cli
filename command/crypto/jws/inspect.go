package jws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/jose"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func inspectCommand() cli.Command {
	return cli.Command{
		Name:   "inspect",
		Action: cli.ActionFunc(inspectAction),
		Usage:  `return the decoded JWS without verification`,
		UsageText: `**step crypto jws inspect**
**--insecure** [**--json**]`,
		Description: `**step crypto jws inspect** reads a JWS data structure from STDIN, decodes it,
and outputs the payload on STDERR. Since this command does not verify the JWS
you must pass **--insecure** as a misuse prevention mechanism.

For examples, see **step help crypto jws**.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name: "json",
				Usage: `Displays the header, payload and signature as a JSON object. The payload will
be encoded using Base64.`,
			},
			flags.InsecureHidden,
		},
	}
}

func inspectAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 0); err != nil {
		return err
	}

	if !ctx.Bool("insecure") {
		return errs.InsecureCommand(ctx)
	}

	token, err := utils.ReadString(os.Stdin)
	if err != nil {
		return err
	}

	tok, err := jose.ParseJWS(token)
	if err != nil {
		return errors.Wrap(jose.TrimPrefix(err), "error parsing token")
	}

	if ctx.Bool("json") {
		return printToken(tok)
	}

	os.Stdout.Write(tok.UnsafePayloadWithoutVerification())
	return nil
}

func printToken(tok *jose.JSONWebSignature) error {
	token, err := tok.CompactSerialize()
	if err != nil {
		return errors.Wrap(jose.TrimPrefix(err), "error serializing token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("error decoding token: JWS must have three parts")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.Wrapf(err, "error decoding token")
	}

	m := make(map[string]json.RawMessage)
	m["header"] = header
	m["payload"] = []byte(`"` + parts[1] + `"`)
	m["signature"] = []byte(`"` + parts[2] + `"`)

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errors.Wrapf(err, "error marshaling token data")
	}

	fmt.Println(string(b))
	return nil
}
