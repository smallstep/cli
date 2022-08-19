package cautils

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/flags"
	caclient "github.com/smallstep/cli/utils/cautils/client"
	"github.com/smallstep/cli/utils/sansutils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/ui"
)

// NewClient returns a client of an online or offline CA. Requires the flags
// `offline`, `ca-config`, `ca-url`, and `root`.
func NewClient(ctx *cli.Context, opts ...ca.ClientOption) (caclient.CaClient, error) {
	if ctx.Bool("offline") {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		return NewOfflineCA(ctx, caConfig)
	}
	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return nil, err
	}
	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return nil, errs.RequiredFlag(ctx, "root")
		}
	}
	opts = append([]ca.ClientOption{ca.WithRootFile(root)}, opts...)
	return ca.NewClient(caURL, opts...)
}

// NewAdminClient returns a client for the mgmt API of the online CA.
func NewAdminClient(ctx *cli.Context, opts ...ca.ClientOption) (*ca.AdminClient, error) {
	caURL, err := flags.ParseCaURLIfExists(ctx)
	if err != nil {
		return nil, err
	}
	if caURL == "" {
		return nil, errs.RequiredFlag(ctx, "ca-url")
	}
	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return nil, errs.RequiredFlag(ctx, "root")
		}
	}

	var (
		adminCertFile = ctx.String("admin-cert")
		adminKeyFile  = ctx.String("admin-key")
		adminCert     []*x509.Certificate
		adminKey      interface{}
	)
	if len(adminCertFile) > 0 || len(adminKeyFile) > 0 {
		if adminCertFile == "" {
			return nil, errs.RequiredWithFlag(ctx, "admin-key", "admin-cert")
		}
		if adminKeyFile == "" {
			return nil, errs.RequiredWithFlag(ctx, "admin-cert", "admin-key")
		}
		adminCert, err = pemutil.ReadCertificateBundle(adminCertFile)
		if err != nil {
			return nil, errors.Wrap(err, "error reading admin certificate")
		}
		adminKey, err = pemutil.Read(adminKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "error reading admin key")
		}
	} else {
		ui.Printf("No admin credentials found. You must login to execute admin commands.\n")
		// Generate a new admin cert/key in memory.
		client, err := ca.NewClient(caURL, ca.WithRootFile(root))
		if err != nil {
			return nil, err
		}
		subject := ctx.String("admin-subject")
		if subject == "" {
			subject, err = ui.Prompt("Please enter admin name/subject (e.g., name@example.com)", ui.WithValidateNotEmpty())
			if err != nil {
				return nil, err
			}
		}
		tok, err := NewTokenFlow(ctx, SignType, subject, []string{subject}, caURL, root, time.Time{}, time.Time{}, provisioner.TimeDuration{}, provisioner.TimeDuration{})

		if err != nil {
			return nil, err
		}

		dnsNames, ips, emails, uris := sansutils.Split([]string{subject})
		template := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: subject,
			},
			DNSNames:       dnsNames,
			IPAddresses:    ips,
			EmailAddresses: emails,
			URIs:           uris,
		}

		adminKey, err = keys.GenerateDefaultKey()
		if err != nil {
			return nil, err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, template, adminKey)
		if err != nil {
			return nil, errors.Wrap(err, "error creating admin certificate request")
		}
		cr, err := x509.ParseCertificateRequest(csr)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing admin certificate request")
		}
		if err := cr.CheckSignature(); err != nil {
			return nil, errors.Wrap(err, "error signing admin certificate request")
		}
		signRequest := &api.SignRequest{
			CsrPEM: api.CertificateRequest{CertificateRequest: cr},
			OTT:    tok,
		}
		signResponse, err := client.Sign(signRequest)
		if err != nil {
			return nil, err
		}
		if signResponse.CertChainPEM == nil || len(signResponse.CertChainPEM) == 0 {
			signResponse.CertChainPEM = []api.Certificate{signResponse.ServerPEM, signResponse.CaPEM}
		}
		adminCert = make([]*x509.Certificate, len(signResponse.CertChainPEM))
		for i, c := range signResponse.CertChainPEM {
			adminCert[i] = c.Certificate
		}
	}

	// Create online client
	opts = append([]ca.ClientOption{ca.WithRootFile(root),
		ca.WithAdminX5C(adminCert, adminKey, ctx.String("password-file"))},
		opts...)
	return ca.NewAdminClient(caURL, opts...)
}
