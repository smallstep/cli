package integration

import (
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ssh/agent"
)

func TestIssuerValiditySSHProxycommandLogin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the real SSH agent fixture uses a Unix socket")
	}

	previousVersion := authority.GlobalVersion
	authority.GlobalVersion.RequireClientAuthentication = true
	t.Cleanup(func() { authority.GlobalVersion = previousVersion })
	f := newIssuerValidityCLI(t)
	home := t.TempDir()
	// Unix socket paths are limited to 104 bytes on macOS.
	t.Chdir(t.TempDir())
	socket := "agent.sock"
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	keyring := agent.NewKeyring()
	go serveIssuerValidityAgent(listener, keyring)
	t.Setenv("SSH_AUTH_SOCK", socket)

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { proxyListener.Close() })
	go func() {
		conn, err := proxyListener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(proxyListener.Addr().String())
	require.NoError(t, err)
	args := []string{
		"ssh", "proxycommand", "ssh.example", host, port,
		"--provisioner", "issuer-validity", "--provisioner-password-file", f.passwordFile,
	}
	stdout, stderr, err := f.run(t, home, args...)
	require.NoError(t, err, "%s", stderr)
	assertCLIWarning(t, stdout, stderr, 1)

	f.assertLeaf(t, filepath.Join(home, "identity", "identity.crt"), f.issuer.NotAfter)

	keys, err := keyring.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestIssuerValiditySSHUnauthorizedLogin(t *testing.T) {
	// Complete a real OIDC device flow with a local provider. The CA verifies the
	// signed ID token and issues the identity; no issuance metadata is mocked.
	key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		new(jose.SignerOptions).WithType("JWT").WithHeader("kid", key.KeyID))
	require.NoError(t, err)
	mux := http.NewServeMux()
	provider := httptest.NewTLSServer(mux)
	t.Cleanup(provider.Close)
	providerRoot := filepath.Join(t.TempDir(), "provider.crt")
	require.NoError(t, os.WriteFile(providerRoot,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0600))
	t.Setenv("STEP_TEST_OIDC_ROOT", providerRoot)
	now := time.Now()
	token, err := jose.Signed(signer).Claims(jose.Claims{
		Issuer: provider.URL, Subject: "user", Audience: []string{"ssh-client"},
		IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(time.Minute)),
	}).Claims(map[string]any{"email": "user@example.com", "email_verified": true}).CompactSerialize()
	require.NoError(t, err)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": provider.URL, "jwks_uri": provider.URL + "/keys",
			"device_authorization_endpoint": provider.URL + "/device",
			"token_endpoint":                provider.URL + "/token",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.Public()}})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "test-device", "user_code": "test-code",
			"verification_uri": provider.URL + "/verify", "interval": 1, "expires_in": 20,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("device_code") != "test-device" {
			http.Error(w, "invalid device code", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": token, "access_token": "test-access", "token_type": "Bearer"})
	})
	enableSSH := true
	oidc := &provisioner.OIDC{
		Type: "OIDC", Name: "identity", ClientID: "ssh-client",
		ConfigurationEndpoint: provider.URL + "/.well-known/openid-configuration",
		Claims: &provisioner.Claims{
			EnableSSHCA:       &enableSSH,
			DefaultUserSSHDur: &provisioner.Duration{Duration: 72 * time.Hour},
			MaxUserSSHDur:     &provisioner.Duration{Duration: 168 * time.Hour},
			DefaultTLSDur:     &provisioner.Duration{Duration: 72 * time.Hour},
			MaxTLSDur:         &provisioner.Duration{Duration: 168 * time.Hour},
		},
	}
	previousVersion := authority.GlobalVersion
	authority.GlobalVersion.RequireClientAuthentication = true
	t.Cleanup(func() { authority.GlobalVersion = previousVersion })
	f := newIssuerValidityCLI(t, func(cfg *config.Config) {
		cfg.AuthorityConfig.Provisioners = append(cfg.AuthorityConfig.Provisioners, oidc)
		cfg.FederatedRoots = append(cfg.FederatedRoots, providerRoot)
	})
	home := t.TempDir()
	// Agent installation is deliberately optional on unauthorized recovery.
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(home, "missing-agent.sock"))
	stdout, stderr, err := f.run(t, home, "ssh", "hosts", "--console")
	require.NoError(t, err, "stdout: %s\nstderr: %s", stdout, stderr)
	require.Contains(t, stdout, "host.example")
	assertCLIWarning(t, stdout, stderr, 1)
	f.assertLeaf(t, filepath.Join(home, "identity", "identity.crt"), f.issuer.NotAfter)
}

func serveIssuerValidityAgent(listener net.Listener, keyring agent.Agent) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = agent.ServeAgent(keyring, conn)
		}()
	}
}
