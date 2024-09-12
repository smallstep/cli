package cautils

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/utils"
)

// CertificateFlow manages the flow to retrieve a new certificate.
type CertificateFlow struct {
	offlineCA *OfflineCA
	offline   bool
}

type flowContext struct {
	DisableCustomSANs       bool
	SSHPublicKey            ssh.PublicKey
	CertificateRequest      *x509.CertificateRequest
	ConfirmationFingerprint string
}

// sharedContext is used to share information between commands.
var sharedContext flowContext

type funcFlowOption struct {
	f func(fo *flowContext)
}

func (ffo *funcFlowOption) apply(fo *flowContext) {
	ffo.f(fo)
}

func newFuncFlowOption(f func(fo *flowContext)) *funcFlowOption {
	return &funcFlowOption{
		f: f,
	}
}

type Option interface {
	apply(fo *flowContext)
}

// WithSSHPublicKey sets the SSH public key used in the request.
func WithSSHPublicKey(key ssh.PublicKey) Option {
	return newFuncFlowOption(func(fo *flowContext) {
		fo.SSHPublicKey = key
	})
}

// WithCertificateRequest sets the X509 certificate request used in the request.
func WithCertificateRequest(cr *x509.CertificateRequest) Option {
	return newFuncFlowOption(func(fo *flowContext) {
		fo.CertificateRequest = cr
	})
}

// WithConfirmationFingerprint sets the confirmation fingerprint used in the
// request.
func WithConfirmationFingerprint(fp string) Option {
	return newFuncFlowOption(func(fo *flowContext) {
		fo.ConfirmationFingerprint = fp
	})
}

// NewCertificateFlow initializes a cli flow to get a new certificate.
func NewCertificateFlow(ctx *cli.Context, opts ...Option) (*CertificateFlow, error) {
	var err error
	var offlineClient *OfflineCA

	// Add options to the shared context
	for _, opt := range opts {
		opt.apply(&sharedContext)
	}

	offline := ctx.Bool("offline")
	if offline {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		offlineClient, err = NewOfflineCA(ctx, caConfig)
		if err != nil {
			return nil, err
		}
	}

	return &CertificateFlow{
		offlineCA: offlineClient,
		offline:   offline,
	}, nil
}

// GetClient returns the client used to send requests to the CA.
func (f *CertificateFlow) GetClient(ctx *cli.Context, tok string, options ...ca.ClientOption) (CaClient, error) {
	if f.offline {
		return f.offlineCA, nil
	}

	// Create online client
	root := ctx.String("root")
	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return nil, err
	}

	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing flag '--token'")
	}
	// Prepare client for bootstrap or provisioning tokens
	if jwt.Payload.SHA != "" && len(jwt.Payload.Audience) > 0 && strings.HasPrefix(strings.ToLower(jwt.Payload.Audience[0]), "http") {
		if caURL == "" {
			caURL = jwt.Payload.Audience[0]
		}
		options = append(options, ca.WithRootSHA256(jwt.Payload.SHA))
	} else {
		if caURL == "" {
			return nil, errs.RequiredFlag(ctx, "ca-url")
		}
		if root == "" {
			root = pki.GetRootCAPath()
			if _, err := os.Stat(root); err != nil {
				return nil, errs.RequiredFlag(ctx, "root")
			}
		}
		options = append(options, ca.WithRootFile(root))
	}

	ui.PrintSelected("CA", caURL)
	return ca.NewClient(caURL, options...)
}

// GenerateToken generates a token for immediate use (therefore only default
// validity values will be used). The token is generated either with the offline
// token flow or the online mode.
func (f *CertificateFlow) GenerateToken(ctx *cli.Context, subject string, sans []string) (string, error) {
	if f.offline {
		return f.offlineCA.GenerateToken(ctx, SignType, subject, sans, time.Time{}, time.Time{}, provisioner.TimeDuration{}, provisioner.TimeDuration{})
	}

	// Use online CA to get the provisioners and generate the token
	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return "", err
	} else if caURL == "" {
		return "", errs.RequiredUnlessFlag(ctx, "ca-url", "token")
	}

	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredUnlessFlag(ctx, "root", "token")
		}
	}

	if subject == "" {
		subject, err = ui.Prompt("What DNS names or IP addresses would you like to use? (e.g. internal.smallstep.com)", ui.WithValidateNotEmpty())
		if err != nil {
			return "", err
		}
	}

	return NewTokenFlow(ctx, SignType, subject, sans, caURL, root, time.Time{}, time.Time{}, provisioner.TimeDuration{}, provisioner.TimeDuration{})
}

// GenerateSSHToken generates a token used to authorize the sign of an SSH
// certificate.
func (f *CertificateFlow) GenerateSSHToken(ctx *cli.Context, subject string, typ int, principals []string, validAfter, validBefore provisioner.TimeDuration) (string, error) {
	if f.offline {
		return f.offlineCA.GenerateToken(ctx, typ, subject, principals, time.Time{}, time.Time{}, validAfter, validBefore)
	}

	// Use online CA to get the provisioners and generate the token
	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return "", err
	} else if caURL == "" {
		return "", errs.RequiredUnlessFlag(ctx, "ca-url", "token")
	}

	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredUnlessFlag(ctx, "root", "token")
		}
	}

	return NewTokenFlow(ctx, typ, subject, principals, caURL, root, time.Time{}, time.Time{}, validAfter, validBefore)
}

// GenerateIdentityToken generates a token using only an OIDC provisioner.
func (f *CertificateFlow) GenerateIdentityToken(ctx *cli.Context) (string, error) {
	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return "", err
	}
	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredFlag(ctx, "root")
		}
	}
	return NewIdentityTokenFlow(ctx, caURL, root)
}

// Sign signs the CSR using the online or the offline certificate authority.
func (f *CertificateFlow) Sign(ctx *cli.Context, tok string, csr api.CertificateRequest, crtFile string) error {
	client, err := f.GetClient(ctx, tok)
	if err != nil {
		return err
	}

	// parse times or durations
	notBefore, notAfter, err := flags.ParseTimeDuration(ctx)
	if err != nil {
		return err
	}

	// parse template data
	templateData, err := flags.ParseTemplateData(ctx)
	if err != nil {
		return err
	}

	req := &api.SignRequest{
		CsrPEM:       csr,
		OTT:          tok,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		TemplateData: templateData,
	}

	resp, err := client.Sign(req)
	if err != nil {
		return err
	}

	if len(resp.CertChainPEM) == 0 {
		resp.CertChainPEM = []api.Certificate{resp.ServerPEM, resp.CaPEM}
	}
	var data []byte
	for _, certPEM := range resp.CertChainPEM {
		pemblk, err := pemutil.Serialize(certPEM.Certificate)
		if err != nil {
			return errors.Wrap(err, "error serializing from step-ca API response")
		}
		data = append(data, pem.EncodeToMemory(pemblk)...)
	}
	return utils.WriteFile(crtFile, data, 0600)
}

// CreateSignRequest is a helper function that given an x509 OTT returns a
// simple but secure sign request as well as the private key used.
func (f *CertificateFlow) CreateSignRequest(ctx *cli.Context, tok, subject string, sans []string) (*api.SignRequest, crypto.PrivateKey, error) {
	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return nil, nil, err
	}

	kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, false, "kty", "curve", "size")
	if err != nil {
		return nil, nil, err
	}
	pk, err := keyutil.GenerateKey(kty, crv, size)
	if err != nil {
		return nil, nil, err
	}

	dnsNames, ips, emails, uris := splitSANs(sans, jwt.Payload.SANs)
	switch jwt.Payload.Type() {
	case token.AWS:
		doc := jwt.Payload.Amazon.InstanceIdentityDocument
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				doc.PrivateIP,
				fmt.Sprintf("ip-%s.%s.compute.internal", strings.ReplaceAll(doc.PrivateIP, ".", "-"), doc.Region),
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips, emails, uris = splitSANs(defaultSANs)
		}
	case token.GCP:
		ce := jwt.Payload.Google.ComputeEngine
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				fmt.Sprintf("%s.c.%s.internal", ce.InstanceName, ce.ProjectID),
				fmt.Sprintf("%s.%s.c.%s.internal", ce.InstanceName, ce.Zone, ce.ProjectID),
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips, emails, uris = splitSANs(defaultSANs)
		}
	case token.Azure:
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				jwt.Payload.Azure.ResourceName,
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips, emails, uris = splitSANs(defaultSANs)
		}
	case token.OIDC:
		// If no sans are given using the --san flag, and the subject argument
		// matches the email then CN=token.sub SANs=email, token.iss#token.sub
		//
		// If no sans are given and the subject argument does not match the
		// email then CN=subject SANs=splitSANs(subject)
		//
		// If sans are provided CN=subject SANs=splitSANs(sans)
		//
		// Note that with the way token types are identified, an OIDC token with
		// `sans` claim will never reach this code. We will leave the condition
		// as it is in case we want it to support it later.
		if len(sans) == 0 && len(jwt.Payload.SANs) == 0 {
			if jwt.Payload.Email != "" && strings.EqualFold(subject, jwt.Payload.Email) {
				subject = jwt.Payload.Subject
				emails = append(emails, jwt.Payload.Email)
				if iss, err := url.Parse(jwt.Payload.Issuer); err == nil && iss.Scheme != "" {
					iss.Fragment = jwt.Payload.Subject
					uris = append(uris, iss)
				}
			} else {
				dnsNames, ips, emails, uris = splitSANs([]string{subject})
			}
		}
	case token.K8sSA:
		// Use subject from command line. K8sSA tokens are multi-use so the
		// subject of the token is not necessarily related to the requested
		// resource.
	default: // Use common name in the token
		subject = jwt.Payload.Subject
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subject,
		},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error creating certificate request")
	}
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing certificate request")
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, nil, errors.Wrap(err, "error signing certificate request")
	}
	return &api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: cr},
		OTT:    tok,
	}, pk, nil
}

// splitSANs unifies the SAN collections passed as arguments and returns a list
// of DNS names, a list of IP addresses, and a list of emails.
func splitSANs(args ...[]string) (dnsNames []string, ipAddresses []net.IP, email []string, uris []*url.URL) {
	m := make(map[string]bool)
	var unique []string
	for _, sans := range args {
		for _, san := range sans {
			if ok := m[san]; !ok && san != "" {
				m[san] = true
				unique = append(unique, san)
			}
		}
	}
	return x509util.SplitSANs(unique)
}
