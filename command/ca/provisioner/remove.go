package provisioner

import (
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func removeCommand() cli.Command {
	return cli.Command{
		Name:   "remove",
		Action: cli.ActionFunc(removeAction),
		Usage:  "remove one, or more, provisioners from the CA configuration",
		UsageText: `**step ca provisioner remove** <name>
		[**--kid**=<kid>] [**--config**=<file>] [**--all**]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-config",
				Usage: "The <file> containing the CA configuration.",
			},
			cli.StringFlag{
				Name:  "kid",
				Usage: "The <kid> (Key ID) of the JWK provisioner key to be removed.",
			},
			cli.StringFlag{
				Name:  "client-id",
				Usage: "The <id> (Client ID) of the OIDC provisioner to be removed.",
			},
			cli.BoolFlag{
				Name: "all",
				Usage: `Remove all provisioners with a given name. Cannot be
used in combination w/ the **--kid** or **--client-id** flag.`,
			},
		},
		Description: `**step ca provisioner remove** removes one or more provisioners
from the configuration and writes the new configuration back to the CA config.

## POSITIONAL ARGUMENTS

<name>
: The name field of the provisioner(s) to be removed.

## EXAMPLES

Remove all provisioners associated with a given name (max@smallstep.com):
'''
$ step ca provisioner remove max@smallstep.com --all --ca-config ca.json
'''

Remove the provisioner matching a given name and kid:
'''
$ step ca provisioner remove max@smallstep. --kid 1234 --ca-config ca.json
'''

Remove the provisioner matching a given name and a client id:
'''
$ step ca provisioner remove Google --ca-config ca.json \
  --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com
'''`,
	}
}

func removeAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	name := ctx.Args().Get(0)
	config := ctx.String("ca-config")
	all := ctx.Bool("all")
	kid := ctx.String("kid")
	clientID := ctx.String("client-id")

	if len(config) == 0 {
		return errs.RequiredFlag(ctx, "ca-config")
	}

	if len(kid) > 0 && len(clientID) > 0 {
		return errs.MutuallyExclusiveFlags(ctx, "kid", "client-id")
	}

	if all {
		if len(kid) != 0 {
			return errs.MutuallyExclusiveFlags(ctx, "all", "kid")
		}
		if len(clientID) != 0 {
			return errs.MutuallyExclusiveFlags(ctx, "all", "client-id")
		}
	} else {
		if len(kid) == 0 && len(clientID) == 0 {
			return errs.RequiredOrFlag(ctx, "all", "kid", "client-id")
		}
	}

	c, err := authority.LoadConfiguration(config)
	if err != nil {
		return errors.Wrapf(err, "error loading configuration")
	}

	var (
		provisioners provisioner.List
		found        = false
	)
	for _, p := range c.AuthorityConfig.Provisioners {
		if p.GetName() != name {
			provisioners = append(provisioners, p)
			continue
		}
		if !all {
			switch pp := p.(type) {
			case *provisioner.JWK:
				if kid == "" || pp.Key.KeyID != kid {
					provisioners = append(provisioners, p)
				}
			case *provisioner.OIDC:
				if clientID == "" || pp.ClientID != clientID {
					provisioners = append(provisioners, p)
				}
			default:
				continue
			}
		}
		found = true
	}

	if !found {
		if all {
			return errors.Errorf("no provisioners with name %s found", name)
		}
		if kid != "" {
			return errors.Errorf("no provisioners with name=%s and kid=%s found", name, kid)
		}
		return errors.Errorf("no provisioners with name=%s and client-id=%s found", name, clientID)
	}

	c.AuthorityConfig.Provisioners = provisioners
	return c.Save(config)
}
