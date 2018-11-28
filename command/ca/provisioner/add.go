package provisioner

import (
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add one or more provisioners the CA configuration",
		UsageText: `**step ca provisioner add** <name> <jwk-file> [<jwk-file> ...]
		[**--ca-config**=<file>] [**--create**]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-config",
				Usage: "The <file> containing the CA configuration.",
			},
			cli.BoolFlag{
				Name:  "create",
				Usage: `Create a new ECDSA key pair using curve P-256 and populate a new provisioner.`,
			},
		},
		Description: `**step ca provisioner add** adds one or more provisioners
to the configuration and writes the new configuration back to the CA config.

## POSITIONAL ARGUMENTS

<name>
: The name linked to all the keys.

<jwk-path>
: List of private (or public) keys in JWK or PEM format.

## EXAMPLES

Add a single provisioner:
'''
$ step ca provisioner add max@smallstep.com ./max-laptop.jwk --ca-config ca.json
'''

Add a single provisioner using an auto-generated asymmetric key pair:
'''
$ step ca provisioner add max@smallstep.com --ca-config ca.json \
--create
'''

Add a list of provisioners for a single name:
'''
$ step ca provisioner add max@smallstep.com ./max-laptop.jwk ./max-phone.pem ./max-work.pem \
--ca-config ca.json
'''`,
	}
}

func addAction(ctx *cli.Context) error {
	if ctx.NArg() < 1 {
		return errs.TooFewArguments(ctx)
	}

	args := ctx.Args()
	name := args[0]

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
		provMap[prov.Name+":"+prov.Key.KeyID] = prov
	}

	create := ctx.Bool("create")

	if create {
		if ctx.NArg() > 1 {
			return errs.IncompatibleFlag(ctx, "create", "<jwk-path> positional arg")
		}
		pass, err := ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]")
		if err != nil {
			return err
		}
		jwk, jwe, err := jose.GenerateDefaultKeyPair(pass)
		if err != nil {
			return err
		}
		encryptedKey, err := jwe.CompactSerialize()
		if err != nil {
			return errors.Wrap(err, "error serializing private key")
		}
		// Check for duplicates
		if _, ok := provMap[name+":"+jwk.KeyID]; ok {
			return errors.Errorf("duplicated provisioner: CA config already contains a provisioner with issuer=%s and kid=%s", name, jwk.KeyID)
		}
		prov := &authority.Provisioner{
			Name:         name,
			Type:         "jwk",
			Key:          jwk,
			EncryptedKey: encryptedKey,
		}
		provisioners = append(provisioners, prov)
		provMap[name+":"+jwk.KeyID] = prov
	} else {
		if ctx.NArg() < 2 {
			return errs.TooFewArguments(ctx)
		}
		jwkFiles := args[1:]
		for _, filename := range jwkFiles {
			jwk, err := jose.ParseKey(filename)
			if err != nil {
				return errs.FileError(err, filename)
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
			if _, ok := provMap[name+":"+jwk.KeyID]; ok {
				return errors.Errorf("duplicated provisioner: CA config already contains a provisioner with issuer=%s and kid=%s", name, jwk.KeyID)
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
				Name:         name,
				Type:         "jwk",
				Key:          &key,
				EncryptedKey: encryptedKey,
			}
			provisioners = append(provisioners, prov)
			provMap[name+":"+jwk.KeyID] = prov
		}
	}

	c.AuthorityConfig.Provisioners = provisioners
	return c.Save(config)
}
