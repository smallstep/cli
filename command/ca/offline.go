package ca

import (
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
)

type offlineProvisionersSelect struct {
	Name         string
	Issuer       string
	Kid          string
	EncryptedKey string
}

// oflineCA is a wrapper on top of the certificates authority methods that
type offlineCA struct {
	authority *authority.Authority
	config    authority.Config
}

// newOfflineCA initializes an offliceCA.
func newOfflineCA(configFile string) (*offlineCA, error) {
	b, err := utils.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config authority.Config
	if err := json.Unmarshal(b, &config); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", configFile)
	}

	if config.AuthorityConfig == nil || len(config.AuthorityConfig.Provisioners) == 0 {
		return nil, errors.Errorf("error parsing %s: no provisioners found", configFile)
	}

	auth, err := authority.New(&config)
	if err != nil {
		return nil, err
	}

	return &offlineCA{
		authority: auth,
		config:    config,
	}, nil
}

// Sign is a wrapper on top of certificates Authorize and Sign methods. It returns the requested certificate with the intermediate.
func (c *offlineCA) Sign(req *api.SignRequest) (*api.SignResponse, error) {
	opts, err := c.authority.Authorize(req.OTT)
	if err != nil {
		return nil, err
	}
	signOpts := authority.SignOptions{
		NotBefore: req.NotBefore,
		NotAfter:  req.NotAfter,
	}
	cert, root, err := c.authority.Sign(req.CsrPEM.CertificateRequest, signOpts, opts...)
	if err != nil {
		return nil, err
	}
	return &api.SignResponse{
		ServerPEM:  api.Certificate{cert},
		CaPEM:      api.Certificate{root},
		TLSOptions: c.authority.GetTLSOptions(),
	}, nil
}

// Renew is a wrapper on top of certificates Renew method. It returns the requested certificate with the intermediate.
func (c *offlineCA) Renew(peer *x509.Certificate) (*x509.Certificate, *x509.Certificate, error) {
	return c.authority.Renew(peer)
}

func (c *offlineCA) GenerateToken(subject string, sans []string, audience, root string, notBefore, notAfter time.Time) (string, error) {
	var kid, issuer, key string

	provisioners := c.config.AuthorityConfig.Provisioners
	if len(provisioners) == 1 {
		kid = provisioners[0].Key.KeyID
		issuer = provisioners[0].Name
		key = provisioners[0].EncryptedKey
	} else {
		var items []*offlineProvisionersSelect
		for _, p := range provisioners {
			items = append(items, &offlineProvisionersSelect{
				Name:         p.Key.KeyID + " (" + p.Name + ")",
				Issuer:       p.Name,
				Kid:          p.Key.KeyID,
				EncryptedKey: p.EncryptedKey,
			})
		}
		i, _, err := ui.Select("What provisioner key do you want to use?", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Key ID")))
		if err != nil {
			return "", err
		}
		kid = items[i].Kid
		issuer = items[i].Issuer
		key = items[i].EncryptedKey
	}

	// Add template with check mark
	opts := []jose.Option{
		jose.WithUIOptions(ui.WithPromptTemplates(ui.PromptTemplates())),
	}

	decrypted, err := jose.Decrypt("Please enter the password to decrypt the provisioner key", []byte(key), opts...)
	if err != nil {
		return "", err
	}

	jwk := new(jose.JSONWebKey)
	if err := json.Unmarshal(decrypted, jwk); err != nil {
		return "", errors.Wrap(err, "error unmarshalling provisioning key")
	}

	return generateToken(subject, sans, kid, issuer, audience, root, notBefore, notAfter, jwk)
}
