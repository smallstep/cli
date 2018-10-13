package provisioner

import (
	"encoding/json"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/authority"
	"github.com/smallstep/ca-component/provisioner"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove one, or more, provisioners from the CA configuration",
		UsageText: `**step ca provisioner remove** <issuer> [**--key-id**=<key-id>]
[**--config**=<file>] [**--all**]`,
		Description: `**step ca provisioner remove** removes one or more provisioners
from the configuration and writes the new configuration back to the CA config`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "config",
				Usage: "<file> containing the CA configuration.",
			},
			cli.StringFlag{
				Name:  "key-id",
				Usage: "Identifier of for the provisioner key to be removed.",
			},
			cli.BoolFlag{
				Name: "all",
				Usage: `Remove all provisioners with a given issuer. Cannot be
used in combination w/ the **--key-id** flag.`,
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

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	issuer := ctx.Args().Get(0)
	config := ctx.String("config")
	all := ctx.Bool("all")
	kid := ctx.String("key-id")
	root := ctx.String("root")
	caURL := ctx.String("ca-url")

	if len(config) == 0 {
		return errs.RequiredFlag(ctx, "config")
	}
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	if all {
		if len(kid) != 0 {
			return errs.MutuallyExclusiveFlags(ctx, "all", "key-id")
		}
	} else {
		if len(kid) == 0 {
			return errs.RequiredUnlessFlag(ctx, "key-id", "all")
		}
	}

	c, err := authority.LoadConfiguration(config)
	if err != nil {
		return errors.Wrapf(err, "error loading configuration")
	}

	ps, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return errors.Wrap(err, "error getting the provisioners")
	}

	var (
		newps []*provisioner.Provisioner
		found = false
	)
	for _, p := range ps {
		if p.Issuer != issuer {
			newps = append(newps, p)
			continue
		}
		if !all && p.Key.KeyID != kid {
			newps = append(newps, p)
			continue
		}
		found = true
	}

	if !found {
		if all {
			return errors.Errorf("No provisioners with issuer %s found", issuer)
		}
		return errors.Errorf("No provisioners with issuer %s and key-id %s", issuer, kid)
	}

	c.AuthorityConfig.Provisioners = newps

	b, err := json.MarshalIndent(c, "", "   ")
	if err != nil {
		return errors.Wrap(err, "error marshaling configuration")
	}

	if err = ioutil.WriteFile(config, b, 0666); err != nil {
		return errs.FileError(err, config)
	}

	return nil
}
