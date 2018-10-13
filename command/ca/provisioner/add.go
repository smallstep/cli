package provisioner

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/authority"
	"github.com/smallstep/ca-component/provisioner"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/urfave/cli"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add one or more provisioners the CA configuration",
		UsageText: `**step ca provisioner add** <issuer> <jwk-path> [**--key-id**=<key-id>]
[**--config**=<file>] [**--ca-url**=<uri>] [**--root**=<file>]`,
		Description: `**step ca provisioner add** adds one or more provisioners
to the configuration and writes the new configuration back to the CA config`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "config",
				Usage: "<file> containing the CA configuration.",
			},
			cli.StringFlag{
				Name:  "key-id",
				Usage: "Identifier of for the provisioner key to be removed.",
			},
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "<URI> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
		},
	}
}

func addAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	issuer := ctx.Args().Get(0)
	jwkPath := ctx.Args().Get(1)
	typ := "jwk"

	config := ctx.String("config")
	kid := ctx.String("key-id")
	root := ctx.String("root")
	caURL := ctx.String("ca-url")

	if len(config) == 0 {
		return errs.RequiredFlag(ctx, "config")
	}
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	fs := strings.Split(jwkPath, ",")

	if len(fs) > 1 && len(kid) != 0 {
		return errs.NewError("--key-id flag is incompatibe with multiple files in --jwk-path")
	}

	ps, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return errors.Wrap(err, "error getting the provisioners")
	}
	m := map[string]*provisioner.Provisioner{}
	for _, p := range ps {
		m[p.Issuer+":"+p.Key.KeyID] = p
	}

	newps := []*provisioner.Provisioner{}
	for _, f := range fs {
		jwk, err := jose.ParseKey(f)
		if err != nil {
			return errs.FileError(err, jwkPath)
		}
		// Make sure the key we are adding is a public JWK (not private, or symmetric).
		// Puting on symmetric keys for the moment.
		if !jwk.IsPublic() {
			return errs.NewError("--jwk-path %s does not contain a public JWK", f)
		}
		if len(kid) != 0 {
			jwk.KeyID = kid
		}
		if _, ok := m[issuer+":"+jwk.KeyID]; ok {
			return errs.NewError("CA already has issuer %s with key-id %s from "+
				" file %s. No keys were added to the configuration. Please remove the offending "+
				"key from --jwk-path and rerun this command.", issuer, jwk.KeyID, f)
		}
		newps = append(newps, &provisioner.Provisioner{
			Issuer: issuer,
			Type:   typ,
			Key:    jwk,
		})
	}
	ps = append(ps, newps...)

	c, err := authority.LoadConfiguration(config)
	if err != nil {
		return errors.Wrapf(err, "error loading configuration")
	}
	c.AuthorityConfig.Provisioners = ps

	b, err := json.MarshalIndent(c, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling configuration")
	}

	if err = ioutil.WriteFile(config, b, 0666); err != nil {
		return errs.FileError(err, config)
	}

	return nil
}
