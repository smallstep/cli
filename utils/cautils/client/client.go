package client

import (
	"crypto/x509"
	"net/http"

	"github.com/smallstep/certificates/api"
)

// CaClient is the interface implemented by a client used to sign, renew, revoke
// certificates among other things.
type CaClient interface {
	Sign(req *api.SignRequest) (*api.SignResponse, error)
	Renew(tr http.RoundTripper) (*api.SignResponse, error)
	Revoke(req *api.RevokeRequest, tr http.RoundTripper) (*api.RevokeResponse, error)
	Rekey(req *api.RekeyRequest, tr http.RoundTripper) (*api.SignResponse, error)
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
	GetCaURL() string
}
