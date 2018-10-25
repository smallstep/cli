package provisioner

import (
	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/authority"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/urfave/cli"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add one or more provisioners the CA configuration",
		UsageText: `**step ca provisioner add** <issuer> <jwk-file> [<jwk-file> ...]
		[**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-config",
				Usage: "The <file> containing the CA configuration.",
			},
		},
		Description: `**step ca provisioner add** adds one or more provisioners
to the configuration and writes the new configuration back to the CA config.

## POSITIONAL ARGUMENTS

<issuer>
: The issuer linked to all the keys.

<jwk-path>
: List of private (or public) keys in JWK or PEM format.

## EXAMPLES

Add a single provisioner:
'''
$ step ca provisioner add max@smallstep.com max-laptop.jwk --ca-config ca.json
'''

Add a list of provisioners for a single issuer:
'''
$ step ca provisioner add max@smallstep.com max-laptop.jwk max-phone.pem max-work.pem \
--ca-config ca.json
'''`,
	}
}

func addAction(ctx *cli.Context) error {
	if ctx.NArg() < 2 {
		return errs.TooFewArguments(ctx)
	}

	args := ctx.Args()
	issuer := args[0]
	jwkFiles := args[1:]

	config := ctx.String("ca-config")
	if len(config) == 0 {
		return errs.RequiredFlag(ctx, "ca-config")
	}

	c, err := authority.LoadConfiguration(config)
	if err != nil {
		return errors.Wrapf(err, "error loading configuration")
	}

	var provisioners []*authority.Provisioner
	provMap := make(map[string]*authority.Provisioner)
	for _, prov := range c.AuthorityConfig.Provisioners {
		provisioners = append(provisioners, prov)
		provMap[prov.Issuer+":"+prov.Key.KeyID] = prov
	}

	for _, name := range jwkFiles {
		jwk, err := jose.ParseKey(name)
		if err != nil {
			return errs.FileError(err, name)
		}
		// Only use asymmetric cryptography
		if _, ok := jwk.Key.([]byte); ok {
			return errors.New("invalid JWK: a symmetric key cannot be used as a provisioner")
		}
		if len(jwk.KeyID) == 0 {
			jwk.KeyID, err = jose.Thumbprint(jwk)
			if err != nil {
				return err
			}
		}
		// Check for duplicates
		if _, ok := provMap[issuer+":"+jwk.KeyID]; ok {
			return errors.Errorf("duplicated provisioner: CA config has already a provisioner with issuer=%s and kid=%s", issuer, jwk.KeyID)
		}
		// Encrypt JWK
		var encryptedKey string
		if !jwk.IsPublic() {
			jwe, err := jose.EncryptJWK(jwk)
			if err != nil {
				return err
			}
			encryptedKey, err = jwe.CompactSerialize()
			if err != nil {
				return errors.Wrap(err, "error serializing private key")
			}
		}
		key := jwk.Public()
		prov := &authority.Provisioner{
			Issuer:       issuer,
			Type:         "jwk",
			Key:          &key,
			EncryptedKey: encryptedKey,
		}
		provisioners = append(provisioners, prov)
		provMap[issuer+":"+jwk.KeyID] = prov
	}

	c.AuthorityConfig.Provisioners = provisioners
	if err := c.Save(config); err != nil {
		return err
	}

	return nil
}
