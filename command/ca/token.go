package ca

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/smallstep/cli/jose"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

const defaultSignatureAlgorithm = "ES256"

func newTokenCommand() cli.Command {
	return cli.Command{
		Name:   "new-token",
		Action: cli.ActionFunc(newTokenAction),
		Usage:  "generates an OTT granting access to the CA",
		UsageText: `**step ca new-token** <hostname>
		[--**kid**=<kid>] [**--ca-url**=<uri>] [**--root**=<file>]
		[**--password-file**=<file>] [**--output-file**=<file>]`,
		Description: `**step ca new-token** command generates a one-time token granting access to the
certificates authority`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "kid",
				Usage: "The provisioner <kid> to use.",
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
			cli.StringFlag{
				Name: "password-file",
				Usage: `The path to the <file> containing the password to decrypt the one-time token
generating key.`,
			},
			cli.StringFlag{
				Name:  "output-file",
				Usage: "The destination <file> of the generated one-time token.",
			},
		},
	}
}

func newTokenAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	root := ctx.String("root")
	caURL := ctx.String("ca-url")
	kid := ctx.String("kid")
	passwordFile := ctx.String("password-file")
	outputFile := ctx.String("output-file")
	subject := ctx.Args().Get(0)

	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	if len(kid) == 0 {
		provisioners, err := pki.GetProvisioners(caURL, root)
		if err != nil {
			return err
		}
		if len(provisioners) == 0 {
			return errors.New("cannot create a new token: the CA does not have any provisioner configured")
		}

		keys := make(map[string]jose.JSONWebKey)
		for issuer, keySet := range provisioners {
			for _, key := range keySet.Keys {
				keys[key.KeyID] = key
				fmt.Fprintf(os.Stderr, "Issuer: %s \tKid: %s\n", issuer, key.KeyID)
			}
		}

		for {
			fmt.Fprintln(os.Stderr)
			fmt.Fprint(os.Stderr, "What provisioner kid do you want to use? ")
			kid, err = utils.ReadString(os.Stdin)
			if err != nil {
				return err
			}
			if _, ok := keys[kid]; ok {
				break
			} else {
				fmt.Fprintln(os.Stderr, "The kid provided does not exist.")
			}
		}
	}

	encrypted, err := pki.GetProvisionerKey(caURL, root, kid)
	if err != nil {
		return err
	}

	var opts []jose.Option
	if len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}

	decrypted, err := jose.Decrypt("Please enter the password to decrypt the provisioner key:", []byte(encrypted), opts...)
	if err != nil {
		return err
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &jwk); err != nil {
		return errors.Wrap(err, "error unmarshalling provisioning key")
	}

	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return err
	}

	// Generate token
	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
	}
	if len(root) > 0 {
		tokOptions = append(tokOptions, token.WithRootCA(root))
	}
	if len(caURL) > 0 {
		tokOptions = append(tokOptions, token.WithCA(caURL))
	}

	tok, err := provision.New(subject, tokOptions...)
	if err != nil {
		return err
	}

	token, err := tok.SignedString(jwk.Algorithm, jwk.Key)
	if err != nil {
		return err
	}

	if len(outputFile) > 0 {
		return utils.WriteFile(outputFile, []byte(token), 0600)
	}
	fmt.Println(token)
	return nil
}
