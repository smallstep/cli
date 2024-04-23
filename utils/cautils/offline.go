package cautils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
	"golang.org/x/crypto/ssh"
)

// OfflineCA is a wrapper on top of the certificates authority methods that is
// used to sign certificates without an online CA.
type OfflineCA struct {
	authority  *authority.Authority
	config     config.Config
	configFile string
}

// offlineInstance is a singleton used for OfflineCA. The use of a singleton is
// necessary to avoid double initialization. Double initializations are
// sometimes not possible due to locks - as seen in badgerDB
var offlineInstance *OfflineCA

// NewOfflineCA initializes an offlineCA.
func NewOfflineCA(ctx *cli.Context, configFile string) (*OfflineCA, error) {
	if offlineInstance != nil {
		return offlineInstance, nil
	}

	b, err := utils.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var cfg config.Config
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, errors.Wrapf(err, "error reading %s", configFile)
	}

	if cfg.AuthorityConfig == nil || len(cfg.AuthorityConfig.Provisioners) == 0 {
		return nil, errors.Errorf("error parsing %s: no provisioners found", configFile)
	}

	if ctx.String("password-file") != "" {
		passFile := ctx.String("password-file")
		pass, err := utils.ReadPasswordFromFile(passFile)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading %s", passFile)
		}
		cfg.Password = string(pass)
	}

	auth, err := authority.New(&cfg)
	if err != nil {
		return nil, err
	}

	offlineInstance = &OfflineCA{
		authority:  auth,
		config:     cfg,
		configFile: configFile,
	}
	return offlineInstance, nil
}

// GetCaURL returns the configured CA url.
func (c *OfflineCA) GetCaURL() string {
	return "https://" + c.config.DNSNames[0]
}

// GetRootCAs return the cert pool for the ca, as it's an offline ca, a pool is
// not required and it always returns nil.
func (c *OfflineCA) GetRootCAs() *x509.CertPool {
	return nil
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
		return fmt.Sprintf("https://%s/revoke", toHostname(c.config.DNSNames[0]))
	case SSHUserSignType, SSHHostSignType:
		return fmt.Sprintf("https://%s/ssh/sign", toHostname(c.config.DNSNames[0]))
	case SSHRenewType:
		return fmt.Sprintf("https://%s/ssh/renew", toHostname(c.config.DNSNames[0]))
	case SSHRevokeType:
		return fmt.Sprintf("https://%s/ssh/revoke", toHostname(c.config.DNSNames[0]))
	case SSHRekeyType:
		return fmt.Sprintf("https://%s/ssh/rekey", toHostname(c.config.DNSNames[0]))
	case RenewType:
		return fmt.Sprintf("https://%s/renew", toHostname(c.config.DNSNames[0]))
	default:
		return fmt.Sprintf("https://%s/sign", toHostname(c.config.DNSNames[0]))
	}
}

// CaURL returns the CA URL using the first DNS entry.
func (c *OfflineCA) CaURL() string {
	return fmt.Sprintf("https://%s", toHostname(c.config.DNSNames[0]))
}

// Root returns the path of the file used as root certificate.
func (c *OfflineCA) Root() string {
	return c.config.Root.First()
}

// Provisioners returns the list of configured provisioners.
func (c *OfflineCA) Provisioners() provisioner.List {
	return c.config.AuthorityConfig.Provisioners
}

func certChainToPEM(certChain []*x509.Certificate) []api.Certificate {
	certChainPEM := make([]api.Certificate, 0, len(certChain))
	for _, c := range certChain {
		certChainPEM = append(certChainPEM, api.Certificate{Certificate: c})
	}
	return certChainPEM
}

// Version is a wrapper on top of the Version method. It returns
// an api.VersionResponse.
func (c *OfflineCA) Version() (*api.VersionResponse, error) {
	v := c.authority.Version()
	return &api.VersionResponse{
		Version:                     v.Version,
		RequireClientAuthentication: v.RequireClientAuthentication,
	}, nil
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
	signOpts := provisioner.SignOptions{
		NotBefore:    req.NotBefore,
		NotAfter:     req.NotAfter,
		TemplateData: req.TemplateData,
	}
	certChain, err := c.authority.SignWithContext(ctx, req.CsrPEM.CertificateRequest, signOpts, opts...)
	if err != nil {
		return nil, err
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM api.Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}
	return &api.SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   c.authority.GetTLSOptions(),
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
	certChain, err := c.authority.Renew(peer)
	if err != nil {
		return nil, err
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM api.Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}
	return &api.SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   c.authority.GetTLSOptions(),
	}, nil
}

// RenewWithToken is a wrapper on top of certificates AuthorizeRenew and Renew
// method. It returns an api.SignResponse with the requested certificate and the
// intermediate.
func (c *OfflineCA) RenewWithToken(ott string) (*api.SignResponse, error) {
	cert, err := c.authority.AuthorizeRenewToken(context.Background(), ott)
	if err != nil {
		return nil, err
	}
	certChain, err := c.authority.Renew(cert)
	if err != nil {
		return nil, err
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM api.Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}
	return &api.SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   c.authority.GetTLSOptions(),
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
		ctx = provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod)
		err error
	)
	if req.OTT != "" {
		opts.OTT = req.OTT
		opts.MTLS = false
		if _, err = c.authority.Authorize(ctx, opts.OTT); err != nil {
			return nil, err
		}
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
	if err := c.authority.Revoke(ctx, &opts); err != nil {
		return nil, err
	}

	return &api.RevokeResponse{Status: "ok"}, nil
}

// Rekey implements the step-ca client interface Rekey method for an offline client.
func (c *OfflineCA) Rekey(req *api.RekeyRequest, rt http.RoundTripper) (*api.SignResponse, error) {
	// it should not panic as this is always internal code
	tr := rt.(*http.Transport)
	asn1Data := tr.TLSClientConfig.Certificates[0].Certificate[0]
	peer, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	// rekey cert using authority

	certChain, err := c.authority.Rekey(peer, req.CsrPEM.PublicKey)
	if err != nil {
		return nil, err
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM api.Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}
	return &api.SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   c.authority.GetTLSOptions(),
	}, nil
}

// SSHSign is a wrapper on top of certificate Authorize and SignSSH methods. It
// returns an api.SSHSignResponse with the signed certificate.
func (c *OfflineCA) SSHSign(req *api.SSHSignRequest) (*api.SSHSignResponse, error) {
	publicKey, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing publicKey")
	}
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SSHSignMethod)
	opts, err := c.authority.Authorize(ctx, req.OTT)
	if err != nil {
		return nil, err
	}
	signOpts := provisioner.SignSSHOptions{
		CertType:     req.CertType,
		KeyID:        req.KeyID,
		Principals:   req.Principals,
		ValidAfter:   req.ValidAfter,
		ValidBefore:  req.ValidBefore,
		TemplateData: req.TemplateData,
	}
	cert, err := c.authority.SignSSH(context.Background(), publicKey, signOpts, opts...)
	if err != nil {
		return nil, err
	}
	return &api.SSHSignResponse{
		Certificate: api.SSHCertificate{
			Certificate: cert,
		},
	}, nil
}

// SSHRevoke is a wrapper on top of certificates SSHRevoke method. It returns an
// api.SSHRevokeResponse.
func (c *OfflineCA) SSHRevoke(req *api.SSHRevokeRequest) (*api.SSHRevokeResponse, error) {
	opts := authority.RevokeOptions{
		Serial:      req.Serial,
		Reason:      req.Reason,
		ReasonCode:  req.ReasonCode,
		PassiveOnly: req.Passive,
		OTT:         req.OTT,
		MTLS:        false,
	}

	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRevokeMethod)
	if _, err := c.authority.Authorize(ctx, opts.OTT); err != nil {
		return nil, err
	}
	if err := c.authority.Revoke(ctx, &opts); err != nil {
		return nil, err
	}

	return &api.SSHRevokeResponse{Status: "ok"}, nil
}

// SSHRenew is a wrapper on top of certificates SSHRenew method. It returns an
// api.SSHRenewResponse.
func (c *OfflineCA) SSHRenew(req *api.SSHRenewRequest) (*api.SSHRenewResponse, error) {
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRenewMethod)
	_, err := c.authority.Authorize(ctx, req.OTT)
	if err != nil {
		return nil, err
	}
	oldCert, _, err := provisioner.ExtractSSHPOPCert(req.OTT)
	if err != nil {
		return nil, err
	}
	cert, err := c.authority.RenewSSH(context.Background(), oldCert)
	if err != nil {
		return nil, err
	}

	return &api.SSHRenewResponse{Certificate: api.SSHCertificate{Certificate: cert}}, nil
}

// SSHRekey is a wrapper on top of certificates SSHRekey method. It returns an
// api.SSHRekeyResponse.
func (c *OfflineCA) SSHRekey(req *api.SSHRekeyRequest) (*api.SSHRekeyResponse, error) {
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SSHRekeyMethod)
	signOpts, err := c.authority.Authorize(ctx, req.OTT)
	if err != nil {
		return nil, err
	}
	oldCert, _, err := provisioner.ExtractSSHPOPCert(req.OTT)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		return nil, err
	}

	cert, err := c.authority.RekeySSH(context.Background(), oldCert, sshPub, signOpts...)
	if err != nil {
		return nil, err
	}

	return &api.SSHRekeyResponse{Certificate: api.SSHCertificate{Certificate: cert}}, nil
}

// SSHRoots is a wrapper on top of the GetSSHRoots method. It returns an
// api.SSHRootsResponse.
func (c *OfflineCA) SSHRoots() (*api.SSHRootsResponse, error) {
	keys, err := c.authority.GetSSHRoots(context.Background())
	if err != nil {
		return nil, err
	}

	resp := new(api.SSHRootsResponse)
	for _, k := range keys.HostKeys {
		resp.HostKeys = append(resp.HostKeys, api.SSHPublicKey{PublicKey: k})
	}
	for _, k := range keys.UserKeys {
		resp.UserKeys = append(resp.UserKeys, api.SSHPublicKey{PublicKey: k})
	}

	return resp, nil
}

// SSHFederation is a wrapper on top of the GetSSHFederation method. It returns
// an api.SSHRootsResponse.
func (c *OfflineCA) SSHFederation() (*api.SSHRootsResponse, error) {
	keys, err := c.authority.GetSSHFederation(context.Background())
	if err != nil {
		return nil, err
	}

	resp := new(api.SSHRootsResponse)
	for _, k := range keys.HostKeys {
		resp.HostKeys = append(resp.HostKeys, api.SSHPublicKey{PublicKey: k})
	}
	for _, k := range keys.UserKeys {
		resp.UserKeys = append(resp.UserKeys, api.SSHPublicKey{PublicKey: k})
	}

	return resp, nil
}

// SSHConfig is a wrapper on top of the GetSSHConfig method. It returns an
// api.SSHConfigResponse.
func (c *OfflineCA) SSHConfig(req *api.SSHConfigRequest) (*api.SSHConfigResponse, error) {
	ts, err := c.authority.GetSSHConfig(context.Background(), req.Type, req.Data)
	if err != nil {
		return nil, err
	}

	var cfg api.SSHConfigResponse
	switch req.Type {
	case provisioner.SSHUserCert:
		cfg.UserTemplates = ts
	case provisioner.SSHHostCert:
		cfg.UserTemplates = ts
	default:
		return nil, errors.New("it should hot get here")
	}

	return &cfg, nil
}

// SSHCheckHost is a wrapper on top of the CheckSSHHost method. It returns an
// api.SSHCheckPrincipalResponse.
func (c *OfflineCA) SSHCheckHost(principal, tok string) (*api.SSHCheckPrincipalResponse, error) {
	exists, err := c.authority.CheckSSHHost(context.Background(), principal, tok)
	if err != nil {
		return nil, err
	}
	return &api.SSHCheckPrincipalResponse{
		Exists: exists,
	}, nil
}

// SSHGetHosts is a wrapper on top of the CheckSSHHost method. It returns an
// api.SSHCheckPrincipalResponse.
func (c *OfflineCA) SSHGetHosts() (*api.SSHGetHostsResponse, error) {
	hosts, err := c.authority.GetSSHHosts(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	return &api.SSHGetHostsResponse{
		Hosts: hosts,
	}, nil
}

// SSHBastion is a wrapper on top of the GetSSHBastion method. It returns an
// api.SSHBastionResponse.
func (c *OfflineCA) SSHBastion(req *api.SSHBastionRequest) (*api.SSHBastionResponse, error) {
	bastion, err := c.authority.GetSSHBastion(context.Background(), req.User, req.Hostname)
	if err != nil {
		return nil, err
	}
	return &api.SSHBastionResponse{
		Hostname: req.Hostname,
		Bastion:  bastion,
	}, nil
}

// GenerateToken creates the token used by the authority to authorize requests.
func (c *OfflineCA) GenerateToken(ctx *cli.Context, tokType int, subject string, sans []string, notBefore, notAfter time.Time, certNotBefore, certNotAfter provisioner.TimeDuration) (string, error) {
	// Use ca.json configuration for the root and audience
	root := c.Root()
	audience := c.Audience(tokType)

	// All provisioners use the same type of tokens to do a X.509 renewal.
	if tokType == RenewType {
		return generateRenewToken(ctx, audience, subject)
	}

	// Get provisioner to use
	provisioners := c.Provisioners()
	p, err := provisionerPrompt(ctx, provisioners)
	if err != nil {
		return "", err
	}

	tokAttrs := tokenAttrs{
		subject:       subject,
		root:          root,
		caURL:         c.CaURL(),
		audience:      audience,
		sans:          sans,
		notBefore:     notBefore,
		notAfter:      notAfter,
		certNotBefore: certNotBefore,
		certNotAfter:  certNotAfter,
	}

	switch p := p.(type) {
	case *provisioner.OIDC: // Run step oauth.
		return generateOIDCToken(ctx, p)
	case *provisioner.X5C: // Get a JWT with an X5C header and signature.
		return generateX5CToken(ctx, p, tokType, tokAttrs)
	case *provisioner.SSHPOP: // Generate an SSHPOP token using ssh cert + key.
		return generateSSHPOPToken(ctx, p, tokType, tokAttrs)
	case *provisioner.Nebula: // Generate an JWK with an nebula header and signature.
		return generateNebulaToken(ctx, p, tokType, tokAttrs)
	case *provisioner.K8sSA: // Get the Kubernetes service account token.
		return generateK8sSAToken(ctx)
	case *provisioner.GCP: // Do the identity request to get the token.
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, c.CaURL())
	case *provisioner.AWS: // Do the identity request to get the token.
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, c.CaURL())
	case *provisioner.Azure: // Do the identity request to get the token.
		sharedContext.DisableCustomSANs = p.DisableCustomSANs
		return p.GetIdentityToken(subject, c.CaURL())
	case *provisioner.ACME: // Return an error with the provisioner ID.
		return "", &ACMETokenError{p.GetName()}
	default: // Default is assumed to be a standard JWT.
		jwkP, ok := p.(*provisioner.JWK)
		if !ok {
			return "", errors.Errorf("unknown provisioner type %T", p)
		}
		return generateJWKToken(ctx, jwkP, tokType, tokAttrs)
	}
}

// toHostname ensures IPv6 addresses are represented as IPv6 hostnames
func toHostname(name string) string {
	if ip := net.ParseIP(name); ip != nil && ip.To4() == nil {
		name = "[" + name + "]"
	}
	return name
}
