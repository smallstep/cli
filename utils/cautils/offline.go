package cautils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
)

// CaClient is the interface implemented by client used to sign, renew, or
// revoke certificates.
type CaClient interface {
	Sign(req *api.SignRequest) (*api.SignResponse, error)
	SignSSH(req *api.SignSSHRequest) (*api.SignSSHResponse, error)
	Renew(tr http.RoundTripper) (*api.SignResponse, error)
	Revoke(req *api.RevokeRequest, tr http.RoundTripper) (*api.RevokeResponse, error)
}

// OfflineCA is a wrapper on top of the certificates authority methods that is
// used to sign certificates without an online CA.
type OfflineCA struct {
	authority  *authority.Authority
	config     authority.Config
	configFile string
}

// NewOfflineCA initializes an offlineCA.
func NewOfflineCA(configFile string) (*OfflineCA, error) {
	b, err := utils.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config authority.Config
	if err = json.Unmarshal(b, &config); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", configFile)
	}

	if config.AuthorityConfig == nil || len(config.AuthorityConfig.Provisioners) == 0 {
		return nil, errors.Errorf("error parsing %s: no provisioners found", configFile)
	}

	auth, err := authority.New(&config)
	if err != nil {
		return nil, err
	}

	return &OfflineCA{
		authority:  auth,
		config:     config,
		configFile: configFile,
	}, nil
}

// VerifyClientCert verifies and validates the client cert/key pair
// using the offline CA root and intermediate certificates.
func (c *OfflineCA) VerifyClientCert(certFile, keyFile string) error {
	cert, err := pemutil.ReadCertificate(certFile, pemutil.WithFirstBlock())
	if err != nil {
		return err
	}
	key, err := pemutil.Read(keyFile)
	if err != nil {
		return err
	}

	certPem, err := pemutil.Serialize(cert)
	if err != nil {
		return err
	}
	keyPem, err := pemutil.Serialize(key)
	if err != nil {
		return err
	}
	// Validate that the certificate and key match
	if _, err = tls.X509KeyPair(pem.EncodeToMemory(certPem), pem.EncodeToMemory(keyPem)); err != nil {
		return errors.Wrap(err, "error loading x509 key pair")
	}

	rootPool, err := x509util.ReadCertPool(c.Root())
	if err != nil {
		return err
	}
	intermediatePool, err := x509util.ReadCertPool(c.config.IntermediateCert)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	if _, err = cert.Verify(opts); err != nil {
		return errors.Wrapf(err, "failed to verify certificate")
	}

	return nil
}

// Audience returns the token audience.
func (c *OfflineCA) Audience(tokType int) string {
	switch tokType {
	case RevokeType:
		return fmt.Sprintf("https://%s/revoke", c.config.DNSNames[0])
	default:
		return fmt.Sprintf("https://%s/sign", c.config.DNSNames[0])
	}
}

// CaURL returns the CA URL using the first DNS entry.
func (c *OfflineCA) CaURL() string {
	return fmt.Sprintf("https://%s", c.config.DNSNames[0])
}

// Root returns the path of the file used as root certificate.
func (c *OfflineCA) Root() string {
	return c.config.Root.First()
}

// Provisioners returns the list of configured provisioners.
func (c *OfflineCA) Provisioners() provisioner.List {
	return c.config.AuthorityConfig.Provisioners
}

// Sign is a wrapper on top of certificates Authorize and Sign methods. It
// returns an api.SignResponse with the requested certificate and the
// intermediate.
func (c *OfflineCA) Sign(req *api.SignRequest) (*api.SignResponse, error) {
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	opts, err := c.authority.Authorize(ctx, req.OTT)
	if err != nil {
		return nil, err
	}
	signOpts := provisioner.Options{
		NotBefore: req.NotBefore,
		NotAfter:  req.NotAfter,
	}
	cert, ca, err := c.authority.Sign(req.CsrPEM.CertificateRequest, signOpts, opts...)
	if err != nil {
		return nil, err
	}
	return &api.SignResponse{
		ServerPEM:  api.Certificate{Certificate: cert},
		CaPEM:      api.Certificate{Certificate: ca},
		TLSOptions: c.authority.GetTLSOptions(),
	}, nil
}

// SignSSH is a wrapper on top of certificate Authorize and SignSSH methods. It
// returns an api.SignSSHResponse with the signed certificate.
func (c *OfflineCA) SignSSH(req *api.SignSSHRequest) (*api.SignSSHResponse, error) {
	publicKey, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing publicKey")
	}
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignSSHMethod)
	opts, err := c.authority.Authorize(ctx, req.OTT)
	if err != nil {
		return nil, err
	}
	signOpts := provisioner.SSHOptions{
		CertType:    req.CertType,
		Principals:  req.Principals,
		ValidAfter:  req.ValidAfter,
		ValidBefore: req.ValidBefore,
	}
	cert, err := c.authority.SignSSH(publicKey, signOpts, opts...)
	if err != nil {
		return nil, err
	}
	return &api.SignSSHResponse{
		Certificate: api.SSHCertificate{
			Certificate: cert,
		},
	}, nil
}

// Renew is a wrapper on top of certificates Renew method. It returns an
// api.SignResponse with the requested certificate and the intermediate.
func (c *OfflineCA) Renew(rt http.RoundTripper) (*api.SignResponse, error) {
	// it should not panic as this is always internal code
	tr := rt.(*http.Transport)
	asn1Data := tr.TLSClientConfig.Certificates[0].Certificate[0]
	peer, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	// renew cert using authority
	cert, ca, err := c.authority.Renew(peer)
	if err != nil {
		return nil, err
	}
	return &api.SignResponse{
		ServerPEM:  api.Certificate{Certificate: cert},
		CaPEM:      api.Certificate{Certificate: ca},
		TLSOptions: c.authority.GetTLSOptions(),
	}, nil
}

// Revoke is a wrapper on top of certificates Revoke method. It returns an
// api.RevokeResponse.
func (c *OfflineCA) Revoke(req *api.RevokeRequest, rt http.RoundTripper) (*api.RevokeResponse, error) {
	var (
		opts = authority.RevokeOptions{
			Serial:      req.Serial,
			Reason:      req.Reason,
			ReasonCode:  req.ReasonCode,
			PassiveOnly: req.Passive,
		}
		err error
	)
	if len(req.OTT) > 0 {
		opts.OTT = req.OTT
		opts.MTLS = false
	} else {
		// it should not panic as this is always internal code
		tr := rt.(*http.Transport)
		asn1Data := tr.TLSClientConfig.Certificates[0].Certificate[0]
		opts.Crt, err = x509.ParseCertificate(asn1Data)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificate")
		}
		opts.MTLS = true
	}

	// revoke cert using authority
	if err := c.authority.Revoke(&opts); err != nil {
		return nil, err
	}

	return &api.RevokeResponse{Status: "ok"}, nil
}

// GenerateToken creates the token used by the authority to authorize requests.
func (c *OfflineCA) GenerateToken(ctx *cli.Context, typ int, subject string, sans []string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration) (string, error) {
	// Use ca.json configuration for the root and audience
	root := c.Root()
	audience := c.Audience(typ)

	// Get provisioner to use
	provisioners := c.Provisioners()

	p, err := provisionerPrompt(ctx, provisioners)
	if err != nil {
		return "", err
	}

	switch p := p.(type) {
	case *provisioner.OIDC: // Run step oauth
		var out []byte
		out, err = exec.Step("oauth", "--oidc", "--bare",
			"--provider", p.ConfigurationEndpoint,
			"--client-id", p.ClientID, "--client-secret", p.ClientSecret)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	case *provisioner.GCP: // Do the identity request to get the token
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, c.CaURL())
	case *provisioner.AWS: // Do the identity request to get the token
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, c.CaURL())
	case *provisioner.Azure: // Do the identity request to get the token
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, c.CaURL())
	case *provisioner.ACME: // ACME provisioners do not implement the token flow.
		return "", &ErrACMEToken{p.GetID()}
	}

	// JWK provisioner
	prov, ok := p.(*provisioner.JWK)
	if !ok {
		return "", errors.Errorf("unknown provisioner type %T", p)
	}

	kid := prov.Key.KeyID
	issuer := prov.Name
	encryptedKey := prov.EncryptedKey

	// Decrypt encrypted key
	opts := []jose.Option{
		jose.WithUIOptions(ui.WithPromptTemplates(ui.PromptTemplates())),
	}
	if passwordFile := ctx.String("password-file"); len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}

	if len(encryptedKey) == 0 {
		return "", errors.Errorf("provisioner '%s' does not have an 'encryptedKey' property", kid)
	}

	decrypted, err := jose.Decrypt("Please enter the password to decrypt the provisioner key", []byte(encryptedKey), opts...)
	if err != nil {
		return "", err
	}

	jwk := new(jose.JSONWebKey)
	if err := json.Unmarshal(decrypted, jwk); err != nil {
		return "", errors.Wrap(err, "error unmarshalling provisioning key")
	}

	// Generate token
	tokenGen := NewTokenGenerator(kid, issuer, audience, root, notBefore, notAfter, jwk)
	switch typ {
	case SignType:
		return tokenGen.SignToken(subject, sans)
	case RevokeType:
		return tokenGen.RevokeToken(subject)
	case SSHUserSignType:
		return tokenGen.SignSSHToken(subject, provisioner.SSHUserCert, sans, certNotBefore, certNotAfter)
	case SSHHostSignType:
		return tokenGen.SignSSHToken(subject, provisioner.SSHHostCert, sans, certNotBefore, certNotAfter)
	default:
		return tokenGen.Token(subject)
	}
}
