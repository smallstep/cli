package cautils

import (
	"crypto/x509"
	"net/http"
	"os"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
)

// CaClient is the interface implemented by a client used to sign, renew, revoke
// certificates among other things.
type CaClient interface {
	Sign(req *api.SignRequest) (*api.SignResponse, error)
	Renew(tr http.RoundTripper) (*api.SignResponse, error)
	Revoke(req *api.RevokeRequest, tr http.RoundTripper) (*api.RevokeResponse, error)
	SSHSign(req *api.SSHSignRequest) (*api.SSHSignResponse, error)
	SSHRenew(req *api.SSHRenewRequest) (*api.SSHRenewResponse, error)
	SSHRekey(req *api.SSHRekeyRequest) (*api.SSHRekeyResponse, error)
	SSHRevoke(req *api.SSHRevokeRequest) (*api.SSHRevokeResponse, error)
	SSHRoots() (*api.SSHRootsResponse, error)
	SSHFederation() (*api.SSHRootsResponse, error)
	SSHConfig(req *api.SSHConfigRequest) (*api.SSHConfigResponse, error)
	SSHCheckHost(principal string, token string) (*api.SSHCheckPrincipalResponse, error)
	SSHGetHosts() (*api.SSHGetHostsResponse, error)
	SSHBastion(req *api.SSHBastionRequest) (*api.SSHBastionResponse, error)
	Version() (*api.VersionResponse, error)
	GetRootCAs() *x509.CertPool
}

// NewClient returns a client of an online or offline CA. Requires the flags
// `offline`, `ca-config`, `ca-url`, and `root`.
func NewClient(ctx *cli.Context, opts ...ca.ClientOption) (CaClient, error) {
	if ctx.Bool("offline") {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		return NewOfflineCA(caConfig)
	}

	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return nil, err
	}
	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return nil, errs.RequiredFlag(ctx, "root")
		}
	}
	opts = append([]ca.ClientOption{ca.WithRootFile(root)}, opts...)
	return ca.NewClient(caURL, opts...)
}
