package provisioner

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/ui"
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
			cli.StringFlag{
				Name: "type",
				Usage: `The <type> of provisioner to remove. Type is a case-insensitive string
and must be one of:
    **JWK**
    : Uses an JWK key pair to sign provisioning tokens.

    **OIDC**
    : Uses an OpenID Connect provider to sign provisioning tokens.

    **AWS**
    : Uses Amazon AWS instance identity documents.

    **GCP**
    : Use Google instance identity tokens.

    **Azure**
    : Uses Microsoft Azure identity tokens.

    **ACME**
    : Uses ACME protocol.

    **X5C**
    : Uses an X509 Certificate / private key pair to sign provisioning tokens.

    **K8sSA**
    : Uses Kubernetes Service Account tokens.`,
			},
		},
		Description: `**step ca provisioner remove** removes one or more provisioners
from the configuration and writes the new configuration back to the CA config.

To pick up the new configuration you must SIGHUP (kill -1 <pid>) or restart the
step-ca process.

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
'''

Remove the cloud identity provisioner given name and a type:
'''
$ step ca provisioner remove Amazon --ca-config ca.json --type AWS
'''

Remove the ACME provisioner by name:
'''
$ step ca provisioner remove my-acme-provisioner --type acme
'''

Remove an X5C provisioner by name:
'''
$ step ca provisioner remove my-x5c-provisioner --type x5c
'''

Remove a K8sSA provisioner by name:
'''
$ step ca provisioner remove k8sSA-default --type k8sSA
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
	typ := ctx.String("type")

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
		if len(kid) == 0 && len(clientID) == 0 && len(typ) == 0 {
			return errs.RequiredOrFlag(ctx, "all", "kid", "client-id", "type")
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
		if p.GetName() != name || !isProvisionerType(p, typ) {
			provisioners = append(provisioners, p)
			continue
		}
		if !all {
			switch pp := p.(type) {
			case *provisioner.JWK:
				if kid != "" && pp.Key.KeyID != kid {
					provisioners = append(provisioners, p)
				}
			case *provisioner.OIDC:
				if clientID != "" && pp.ClientID != clientID {
					provisioners = append(provisioners, p)
				}
			case *provisioner.AWS, *provisioner.Azure, *provisioner.GCP,
				*provisioner.ACME, *provisioner.X5C, *provisioner.K8sSA:
				// they are filtered by type and name.
			default:
				continue
			}
		}
		found = true
	}

	if !found {
		switch {
		case kid != "":
			return errors.Errorf("no provisioners with name=%s and kid=%s found", name, kid)
		case clientID != "":
			return errors.Errorf("no provisioners with name=%s and client-id=%s found", name, clientID)
		case typ != "":
			return errors.Errorf("no provisioners with name=%s and type=%s found", name, typ)
		default:
			return errors.Errorf("no provisioners with name %s found", name)
		}
	}

	c.AuthorityConfig.Provisioners = provisioners
	if err = c.Save(config); err != nil {
		return err
	}

	ui.Println("Success! Your `step-ca` config has been updated. To pick up the new configuration SIGHUP (kill -1 <pid>) or restart the step-ca process.")

	return nil
}

// isProvisionerType returns true if p.GetType() is equal to typ. If typ is
// empty it will always return true.
func isProvisionerType(p provisioner.Interface, typ string) bool {
	return typ == "" || strings.EqualFold(typ, p.GetType().String())
}
