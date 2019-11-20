package cautils

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

// CertificateFlow manages the flow to retrieve a new certificate.
type CertificateFlow struct {
	offlineCA *OfflineCA
	offline   bool
}

// sharedContext is used to share information between commands.
var sharedContext = struct {
	DisableCustomSANs bool
}{}

// NewCertificateFlow initializes a cli flow to get a new certificate.
func NewCertificateFlow(ctx *cli.Context) (*CertificateFlow, error) {
	var err error
	var offlineClient *OfflineCA

	offline := ctx.Bool("offline")
	if offline {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		offlineClient, err = NewOfflineCA(caConfig)
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
func (f *CertificateFlow) GetClient(ctx *cli.Context, tok string) (CaClient, error) {
	if f.offline {
		return f.offlineCA, nil
	}

	// Create online client
	root := ctx.String("root")
	caURL := ctx.String("ca-url")

	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing flag '--token'")
	}
	// Prepare client for bootstrap or provisioning tokens
	var options []ca.ClientOption
	if len(jwt.Payload.SHA) > 0 && len(jwt.Payload.Audience) > 0 && strings.HasPrefix(strings.ToLower(jwt.Payload.Audience[0]), "http") {
		if len(caURL) == 0 {
			caURL = jwt.Payload.Audience[0]
		}
		options = append(options, ca.WithRootSHA256(jwt.Payload.SHA))
	} else {
		if len(caURL) == 0 {
			return nil, errs.RequiredFlag(ctx, "ca-url")
		}
		if len(root) == 0 {
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
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return "", errs.RequiredUnlessFlag(ctx, "ca-url", "token")
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredUnlessFlag(ctx, "root", "token")
		}
	}

	var err error
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
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return "", errs.RequiredUnlessFlag(ctx, "ca-url", "token")
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredUnlessFlag(ctx, "root", "token")
		}
	}

	var err error
	if subject == "" {
		subject, err = ui.Prompt("What DNS names or IP addresses would you like to use? (e.g. internal.smallstep.com)", ui.WithValidateNotEmpty())
		if err != nil {
			return "", err
		}
	}

	return NewTokenFlow(ctx, typ, subject, principals, caURL, root, time.Time{}, time.Time{}, validAfter, validBefore)
}

// GenerateIdentityToken generates a token using only an OIDC provisioner.
func (f *CertificateFlow) GenerateIdentityToken(ctx *cli.Context) (string, error) {
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return "", errs.RequiredFlag(ctx, "ca-url")
	}
	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredFlag(ctx, "root")
		}
	}
	return NewIdentityTokenFlow(ctx, caURL, root)
}

// Sign signs the CSR using the online or the offline certificate authority.
func (f *CertificateFlow) Sign(ctx *cli.Context, token string, csr api.CertificateRequest, crtFile string) error {
	client, err := f.GetClient(ctx, token)
	if err != nil {
		return err
	}

	// parse times or durations
	notBefore, notAfter, err := parseTimeDuration(ctx)
	if err != nil {
		return err
	}

	req := &api.SignRequest{
		CsrPEM:    csr,
		OTT:       token,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	resp, err := client.Sign(req)
	if err != nil {
		return err
	}

	if resp.CertChainPEM == nil || len(resp.CertChainPEM) == 0 {
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
	pk, err := keys.GenerateKey(kty, crv, size)
	if err != nil {
		return nil, nil, err
	}

	dnsNames, ips, emails := splitSANs(sans, jwt.Payload.SANs)
	switch jwt.Payload.Type() {
	case token.AWS:
		doc := jwt.Payload.Amazon.InstanceIdentityDocument
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				doc.PrivateIP,
				fmt.Sprintf("ip-%s.%s.compute.internal", strings.Replace(doc.PrivateIP, ".", "-", -1), doc.Region),
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips, emails = splitSANs(defaultSANs)
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
			dnsNames, ips, emails = splitSANs(defaultSANs)
		}
	case token.Azure:
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				jwt.Payload.Azure.VirtualMachine,
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips, emails = splitSANs(defaultSANs)
		}
	case token.OIDC:
		if jwt.Payload.Email != "" {
			emails = append(emails, jwt.Payload.Email)
		}
		subject = jwt.Payload.Subject
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
func splitSANs(args ...[]string) (dnsNames []string, ipAddresses []net.IP, email []string) {
	m := make(map[string]bool)
	var unique []string
	for _, sans := range args {
		for _, san := range sans {
			if ok := m[san]; !ok {
				m[san] = true
				unique = append(unique, san)
			}
		}
	}
	return x509util.SplitSANs(unique)
}

// parseTimeDuration parses the not-before and not-after flags as a timeDuration
func parseTimeDuration(ctx *cli.Context) (notBefore api.TimeDuration, notAfter api.TimeDuration, err error) {
	var zero api.TimeDuration
	notBefore, err = api.ParseTimeDuration(ctx.String("not-before"))
	if err != nil {
		return zero, zero, errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, err = api.ParseTimeDuration(ctx.String("not-after"))
	if err != nil {
		return zero, zero, errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	return
}
