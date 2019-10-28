package cautils

import (
	"net/http"
	"os"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
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
	SSHCheckHost(principal string) (*api.SSHCheckPrincipalResponse, error)
	SSHGetHosts() (*api.SSHGetHostsResponse, error)
}

// NewClient returns a client of an online or offline CA. Requires the flags
// `offline`, `ca-config`, `ca-url`, and `root`.
func NewClient(ctx *cli.Context) (CaClient, error) {
	if ctx.Bool("offline") {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		return NewOfflineCA(caConfig)
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return nil, errs.RequiredFlag(ctx, "ca-url")
	}
	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return nil, errs.RequiredFlag(ctx, "root")
		}
	}
	return ca.NewClient(caURL, ca.WithRootFile(root))
}
