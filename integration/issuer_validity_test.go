package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/cli/utils/cautils"
)

// The existing integration TestMain installs the real step entrypoint as an
// executable. These tests use that process and real signed credentials, not a
// mocked client or response transport.
func TestIssuerValidityNativeCommands(t *testing.T) {
	f := newIssuerValidityCLI(t)
	for _, offline := range []bool{false, true} {
		name := "online"
		if offline {
			name = "offline"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			for _, operation := range []string{"certificate", "sign"} {
				t.Run(operation, func(t *testing.T) {
					certFile := filepath.Join(t.TempDir(), "leaf.crt")
					keyFile := filepath.Join(t.TempDir(), "leaf.key")
					args := []string{"ca", operation}
					if operation == "certificate" {
						args = append(args, "native.example", certFile, keyFile)
					} else {
						key, err := keyutil.GenerateDefaultSigner()
						require.NoError(t, err)
						csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
							Subject: pkix.Name{CommonName: "native.example"}, DNSNames: []string{"native.example"},
						}, key)
						require.NoError(t, err)
						csrFile := filepath.Join(t.TempDir(), "leaf.csr")
						require.NoError(t, os.WriteFile(csrFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0600))
						args = append(args, csrFile, certFile)
					}
					args = append(args, "--not-after", "96h")
					if offline {
						args = append(args, f.offlineFlags()...)
					} else {
						args = append(args, "--token", f.signToken(t, "native.example"))
					}
					stdout, stderr, err := f.run(t, home, args...)
					require.NoError(t, err, "%s", stderr)
					assertCLIWarning(t, stdout, stderr, 1)
					f.assertLeaf(t, certFile, f.issuer.NotAfter)
				})
			}
			for _, operation := range []string{"renew", "token-renew", "rekey"} {
				t.Run(operation, func(t *testing.T) {
					certFile, keyFile, oldLeaf := f.oldCredential(t, f.now, f.now.Add(32*time.Hour))
					command := operation
					if command == "token-renew" {
						command = "renew"
					}
					args := []string{"ca", command, certFile, keyFile, "--force"}
					if operation == "token-renew" {
						args = append(args, "--mtls=false")
					}
					if offline {
						args = append(args, "--offline", "--ca-config", f.configFile)
					}
					stdout, stderr, err := f.run(t, home, args...)
					require.NoError(t, err, "%s", stderr)
					assertCLIWarning(t, stdout, stderr, 1)
					leaf := f.assertLeaf(t, certFile, f.issuer.NotAfter)
					pair, err := tls.LoadX509KeyPair(certFile, keyFile)
					require.NoError(t, err)
					require.True(t, keyutil.Equal(leaf.PublicKey, pair.PrivateKey.(crypto.Signer).Public()))
					if operation == "rekey" {
						require.False(t, keyutil.Equal(oldLeaf.PublicKey, leaf.PublicKey))
					} else {
						require.True(t, keyutil.Equal(oldLeaf.PublicKey, leaf.PublicKey))
					}
				})
			}
			// Warning-free replies remain silent. A rejected request must not leave
			// certificate output or produce a success warning.
			for _, test := range []struct {
				name, duration string
				failure        bool
			}{
				{"uncapped", "1h", false},
				{"invalid duration", "200h", true},
			} {
				t.Run(test.name, func(t *testing.T) {
					certFile := filepath.Join(t.TempDir(), "leaf.crt")
					args := []string{"ca", "certificate", "native.example", certFile, filepath.Join(t.TempDir(), "leaf.key"), "--not-after", test.duration}
					if offline {
						args = append(args, f.offlineFlags()...)
					} else {
						args = append(args, "--token", f.signToken(t, "native.example"))
					}
					stdout, stderr, err := f.run(t, home, args...)
					assertCLIWarning(t, stdout, stderr, 0)
					if test.failure {
						require.Error(t, err)
						_, statErr := os.Stat(certFile)
						require.True(t, os.IsNotExist(statErr))
					} else {
						require.NoError(t, err, "%s", stderr)
						bundle, err := pemutil.ReadCertificateBundle(certFile)
						require.NoError(t, err)
						leaf := bundle[0]
						require.True(t, leaf.NotAfter.Before(f.issuer.NotAfter))
						require.NoError(t, leaf.CheckSignatureFrom(f.issuer))
					}
				})
			}
		})
	}
}

func TestIssuerValiditySSHCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the real SSH agent fixture uses a Unix socket")
	}
	f := newIssuerValidityCLI(t)
	home := t.TempDir()
	// Keep the socket address below macOS's 104-byte Unix socket limit.
	t.Chdir(t.TempDir())
	socket := "agent.sock"
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	keyring := agent.NewKeyring()
	go func() {
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
	}()
	t.Setenv("SSH_AUTH_SOCK", socket)
	previousVersion := authority.GlobalVersion
	authority.GlobalVersion.RequireClientAuthentication = true
	t.Cleanup(func() { authority.GlobalVersion = previousVersion })

	for _, operation := range []string{"certificate", "login"} {
		t.Run(operation, func(t *testing.T) {
			args := []string{"ssh", operation, "ssh.example"}
			keyFile := filepath.Join(t.TempDir(), "ssh-key")
			if operation == "certificate" {
				args = append(args, keyFile, "--host", "--no-agent", "--no-password", "--insecure")
			}
			certType := provisioner.SSHUserCert
			if operation == "certificate" {
				certType = provisioner.SSHHostCert
			}
			args = append(args, "--force", "--token", f.sshToken(t, certType), "--not-after", "72h")
			stdout, stderr, err := f.run(t, home, args...)
			require.NoError(t, err, "%s", stderr)
			assertCLIWarning(t, stdout, stderr, 1)
			f.assertLeaf(t, filepath.Join(home, "identity", "identity.crt"), f.issuer.NotAfter)
			if operation == "certificate" {
				cert := readCLISSHCertificate(t, keyFile+"-cert.pub")
				require.Greater(t, time.Unix(int64(cert.ValidBefore), 0).Unix(), f.issuer.NotAfter.Unix())
			} else {
				keys, err := keyring.List()
				require.NoError(t, err)
				require.Len(t, keys, 1)
				pub, err := ssh.ParsePublicKey(keys[0].Blob)
				require.NoError(t, err)
				cert := pub.(*ssh.Certificate)
				require.Greater(t, time.Unix(int64(cert.ValidBefore), 0).Unix(), f.issuer.NotAfter.Unix())
			}
		})
	}

	for _, operation := range []string{"renew", "rekey"} {
		t.Run(operation, func(t *testing.T) {
			keyFile := filepath.Join(t.TempDir(), "ssh-key")
			_, stderr, err := f.run(t, home, "ssh", "certificate", "ssh.example", keyFile, "--host", "--no-agent", "--no-password", "--insecure", "--token", f.sshToken(t, provisioner.SSHHostCert), "--not-after", "72h", "--force")
			require.NoError(t, err, "%s", stderr)
			old := readCLISSHCertificate(t, keyFile+"-cert.pub")
			args := []string{"ssh", operation, keyFile + "-cert.pub", keyFile, "--force"}
			if operation == "rekey" {
				args = append(args, "--no-password", "--insecure")
			}
			stdout, stderr, err := f.run(t, home, args...)
			require.NoError(t, err, "%s", stderr)
			assertCLIWarning(t, stdout, stderr, 1)
			f.assertLeaf(t, filepath.Join(home, "identity", "identity.crt"), f.issuer.NotAfter)
			cert := readCLISSHCertificate(t, keyFile+"-cert.pub")
			require.Equal(t, old.ValidBefore-old.ValidAfter, cert.ValidBefore-cert.ValidAfter)
			require.Greater(t, time.Unix(int64(cert.ValidBefore), 0).Unix(), f.issuer.NotAfter.Unix())
			if operation == "rekey" {
				require.NotEqual(t, old.Key.Marshal(), cert.Key.Marshal())
			} else {
				require.Equal(t, old.Key.Marshal(), cert.Key.Marshal())
			}
		})
	}

	t.Run("online SSH without an identity remains silent", func(t *testing.T) {
		authority.GlobalVersion.RequireClientAuthentication = false
		defer func() { authority.GlobalVersion.RequireClientAuthentication = true }()
		home := t.TempDir()
		keyFile := filepath.Join(t.TempDir(), "ssh-key")
		stdout, stderr, err := f.run(t, home, "ssh", "certificate", "ssh.example", keyFile,
			"--host", "--no-agent", "--no-password", "--insecure", "--not-after", "72h", "--token", f.sshToken(t, provisioner.SSHHostCert))
		require.NoError(t, err, "%s", stderr)
		assertCLIWarning(t, stdout, stderr, 0)
		_, err = os.Stat(filepath.Join(home, "identity", "identity.crt"))
		require.True(t, os.IsNotExist(err))
	})

	t.Run("offline SSH remains identity free", func(t *testing.T) {
		home := t.TempDir()
		keyFile := filepath.Join(t.TempDir(), "ssh-key")
		args := []string{"ssh", "certificate", "ssh.example", keyFile, "--host", "--no-agent", "--no-password", "--insecure", "--not-after", "72h"}
		args = append(args, f.offlineFlags()...)
		stdout, stderr, err := f.run(t, home, args...)
		require.NoError(t, err, "%s", stderr)
		assertCLIWarning(t, stdout, stderr, 0)
		_, err = os.Stat(filepath.Join(home, "identity", "identity.crt"))
		require.True(t, os.IsNotExist(err))
		for _, operation := range []string{"renew", "rekey"} {
			args = []string{"ssh", operation, keyFile + "-cert.pub", keyFile, "--force", "--offline", "--ca-config", f.configFile}
			if operation == "rekey" {
				args = append(args, "--no-password", "--insecure")
			}
			stdout, stderr, err = f.run(t, home, args...)
			require.NoError(t, err, "%s", stderr)
			assertCLIWarning(t, stdout, stderr, 0)
			_, err = os.Stat(filepath.Join(home, "identity", "identity.crt"))
			require.True(t, os.IsNotExist(err))
		}
		args = []string{"ssh", "login", "ssh.example", "--force", "--not-after", "72h"}
		args = append(args, f.offlineFlags()...)
		stdout, stderr, err = f.run(t, home, args...)
		require.NoError(t, err, "%s", stderr)
		assertCLIWarning(t, stdout, stderr, 0)
		_, err = os.Stat(filepath.Join(home, "identity", "identity.crt"))
		require.True(t, os.IsNotExist(err))
	})
}

func readCLISSHCertificate(t *testing.T, path string) *ssh.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	require.NoError(t, err)
	cert, ok := pub.(*ssh.Certificate)
	require.True(t, ok)
	return cert
}

func TestIssuerValidityAdminClient(t *testing.T) {
	f := newIssuerValidityCLI(t)
	t.Setenv("STEPPATH", t.TempDir())
	set := flag.NewFlagSet("admin", flag.ContinueOnError)
	for name, value := range map[string]string{
		"ca-url": f.server.URL, "root": f.rootFile, "admin-subject": "admin.example",
		"admin-provisioner": "issuer-validity", "provisioner-password-file": f.passwordFile,
		"admin-cert": "", "admin-key": "", "password-file": "",
	} {
		set.String(name, value, "")
	}
	ctx := cli.NewContext(cli.NewApp(), set, nil)
	stderr, err := captureCLIStderr(t, func() error {
		_, err := cautils.NewAdminClient(ctx)
		return err
	})
	require.NoError(t, err)
	assertCLIWarning(t, "", stderr, 1)
	certFile, keyFile, _ := f.oldCredential(t, f.now, f.now.Add(time.Hour))
	require.NoError(t, ctx.Set("admin-cert", certFile))
	require.NoError(t, ctx.Set("admin-key", keyFile))
	stderr, err = captureCLIStderr(t, func() error {
		_, err := cautils.NewAdminClient(ctx)
		return err
	})
	require.NoError(t, err)
	assertCLIWarning(t, "", stderr, 0)
}

func captureCLIStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	original := os.Stderr
	os.Stderr = file
	defer func() { os.Stderr = original; file.Close() }()
	operationErr := fn()
	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)
	data, err := io.ReadAll(file)
	require.NoError(t, err)
	return string(data), operationErr
}

func assertCLIWarning(t *testing.T, stdout, stderr string, count int) {
	t.Helper()
	require.NotContains(t, stdout, "WARNING:")
	require.Equal(t, count, strings.Count(stderr, "WARNING:"), "%s", stderr)
	require.Equal(t, count, strings.Count(stderr, "[issuer_validity_truncated]"), "%s", stderr)
}

func TestIssuerValidityUnavailableStderr(t *testing.T) {
	f := newIssuerValidityCLI(t)
	certFile, keyFile := filepath.Join(t.TempDir(), "leaf.crt"), filepath.Join(t.TempDir(), "leaf.key")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "step", "ca", "certificate", "native.example", certFile, keyFile,
		"--not-after", "96h", "--token", f.signToken(t, "native.example"), "--ca-url", f.server.URL, "--root", f.rootFile)
	cmd.Env = append(os.Environ(), "STEPPATH="+t.TempDir())
	// A read-only descriptor makes writes to the child's actual stderr fail.
	stderr, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer stderr.Close()
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, stderr
	require.NoError(t, cmd.Run(), "%s", stdout.String())
	require.NotContains(t, stdout.String(), "WARNING:")
	leaf := f.assertLeaf(t, certFile, f.issuer.NotAfter)
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	require.True(t, keyutil.Equal(leaf.PublicKey, pair.PrivateKey.(crypto.Signer).Public()))
}

func TestIssuerValidityFailedCredentialOutput(t *testing.T) {
	f := newIssuerValidityCLI(t)
	for _, operation := range []string{"certificate", "renew", "rekey"} {
		t.Run(operation, func(t *testing.T) {
			missingFile := filepath.Join(t.TempDir(), "missing", "leaf.crt")
			var args []string
			if operation == "certificate" {
				args = []string{"ca", "certificate", "native.example", missingFile, filepath.Join(t.TempDir(), "leaf.key"),
					"--not-after", "96h", "--token", f.signToken(t, "native.example")}
			} else {
				certFile, keyFile, _ := f.oldCredential(t, f.now, f.now.Add(32*time.Hour))
				args = []string{"ca", operation, certFile, keyFile, "--force"}
				if operation == "renew" {
					args = append(args, "--out", missingFile)
				} else {
					args = append(args, "--out-cert", missingFile, "--out-key", filepath.Join(t.TempDir(), "new.key"))
				}
			}
			stdout, stderr, err := f.run(t, t.TempDir(), args...)
			require.Error(t, err)
			assertCLIWarning(t, stdout, stderr, 0)
			_, err = os.Stat(missingFile)
			require.True(t, os.IsNotExist(err))
		})
	}
}

func TestIssuerValidityDaemonImmediateRenewal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the daemon fixture terminates with a Unix interrupt signal")
	}
	f := newIssuerValidityCLI(t)
	certFile, keyFile, old := f.oldCredential(t, f.now.Add(-4*time.Hour), f.now.Add(28*time.Hour))
	// The fixed period is valid for the original 32h leaf, but is longer than
	// the 30h issuer-capped renewal. The existing daemon consequently schedules
	// another renewal immediately instead of changing the configured period.
	require.Greater(t, old.NotAfter.Sub(old.NotBefore), 31*time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "step", "ca", "renew", certFile, keyFile,
		"--daemon", "--renew-period", "31h", "--ca-url", f.server.URL, "--root", f.rootFile)
	cmd.Env = append(os.Environ(), "STEPPATH="+t.TempDir())
	stdout := &issuerValidityOutput{done: make(chan struct{}), needle: "next in 0s", count: 2}
	stderr := &issuerValidityOutput{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	require.NoError(t, cmd.Start())
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	select {
	case <-stdout.done:
		require.NoError(t, cmd.Process.Signal(os.Interrupt))
		require.NoError(t, <-finished)
	case err := <-finished:
		t.Fatalf("daemon exited before immediate rescheduling: %v\n%s\n%s", err, stdout.String(), stderr.String())
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-finished
		t.Fatalf("daemon did not renew immediately: %s\n%s", stdout.String(), stderr.String())
	}
	require.NotContains(t, stdout.String(), "WARNING:")
	require.Contains(t, stderr.String(), "[issuer_validity_truncated]")
	f.assertLeaf(t, certFile, f.issuer.NotAfter)
}

type issuerValidityOutput struct {
	sync.Mutex
	buffer bytes.Buffer
	done   chan struct{}
	needle string
	count  int
	closed bool
}

func (w *issuerValidityOutput) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	n, err := w.buffer.Write(p)
	if w.done != nil && !w.closed && strings.Count(w.buffer.String(), w.needle) >= w.count {
		close(w.done)
		w.closed = true
	}
	return n, err
}

func (w *issuerValidityOutput) String() string {
	w.Lock()
	defer w.Unlock()
	return w.buffer.String()
}

type issuerValidityCLI struct {
	now                                time.Time
	root, issuer, oldIssuer            *x509.Certificate
	issuerKey                          crypto.Signer
	jwk                                *jose.JSONWebKey
	server                             *httptest.Server
	rootFile, configFile, passwordFile string
}

func newIssuerValidityCLI(t *testing.T, configure ...func(*config.Config)) *issuerValidityCLI {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	mini, err := minica.New(minica.WithName("issuer-validity CLI"))
	require.NoError(t, err)
	rootTemplate := *mini.Root
	rootTemplate.NotBefore, rootTemplate.NotAfter = now.Add(-time.Hour), now.Add(36*time.Hour)
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, mini.RootSigner.Public(), mini.RootSigner)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	issuerTemplate := *mini.Intermediate
	issuerTemplate.NotBefore, issuerTemplate.NotAfter = now.Add(-24*time.Hour), now.Add(48*time.Hour)
	oldDER, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, root, mini.Signer.Public(), mini.RootSigner)
	require.NoError(t, err)
	oldIssuer, err := x509.ParseCertificate(oldDER)
	require.NoError(t, err)
	issuerTemplate.SerialNumber = big.NewInt(3)
	issuerTemplate.NotAfter = now.Add(30 * time.Hour)
	issuerDER, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, root, mini.Signer.Public(), mini.RootSigner)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	require.NoError(t, err)
	publicJWK := jwk.Public()
	encrypted, err := jose.EncryptJWK(jwk, []byte("issuer-validity-test-password"))
	require.NoError(t, err)
	encryptedKey, err := encrypted.CompactSerialize()
	require.NoError(t, err)
	dir := t.TempDir()
	write := func(name string, value any) string {
		path := filepath.Join(dir, name)
		_, err := pemutil.Serialize(value, pemutil.ToFile(path, 0600))
		require.NoError(t, err)
		return path
	}
	enableSSH := true
	claims := &provisioner.Claims{
		MinTLSDur:         &provisioner.Duration{Duration: 5 * time.Minute},
		DefaultTLSDur:     &provisioner.Duration{Duration: 72 * time.Hour},
		MaxTLSDur:         &provisioner.Duration{Duration: 168 * time.Hour},
		DefaultUserSSHDur: &provisioner.Duration{Duration: 72 * time.Hour},
		MaxUserSSHDur:     &provisioner.Duration{Duration: 168 * time.Hour},
		DefaultHostSSHDur: &provisioner.Duration{Duration: 72 * time.Hour},
		EnableSSHCA:       &enableSSH,
	}
	rootFile := write("root.crt", root)
	cfg := &config.Config{
		Root: []string{rootFile}, IntermediateCert: write("issuer.crt", issuer), IntermediateKey: write("issuer.key", mini.Signer),
		Address: "127.0.0.1:0", DNSNames: []string{"127.0.0.1", "localhost"},
		SSH: &config.SSHConfig{HostKey: write("ssh-host.key", mini.Signer), UserKey: write("ssh-user.key", mini.Signer)},
		AuthorityConfig: &config.AuthConfig{
			DisableIssuedAtCheck: true,
			Provisioners: provisioner.List{
				&provisioner.JWK{Type: "JWK", Name: "issuer-validity", Key: &publicJWK, EncryptedKey: encryptedKey, Claims: claims},
				&provisioner.SSHPOP{Type: "SSHPOP", Name: "sshpop", Claims: claims},
			},
		},
	}
	for _, fn := range configure {
		fn(cfg)
	}
	auth, err := authority.New(cfg, authority.WithQuietInit(),
		authority.WithSSHGetHosts(func(_ context.Context, cert *x509.Certificate) ([]config.Host, error) {
			if cert == nil {
				return nil, errs.Unauthorized("client identity required")
			}
			return []config.Host{{Hostname: "host.example"}}, nil
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auth.Shutdown()) })
	mini.Root, mini.Intermediate = root, issuer
	serverKey, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	serverCert, err := mini.Sign(&x509.Certificate{
		Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		PublicKey: serverKey.Public(), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	router := chi.NewRouter()
	api.Route(router)
	server := httptest.NewUnstartedServer(router)
	server.Config.BaseContext = func(net.Listener) context.Context { return authority.NewContext(context.Background(), auth) }
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw, issuer.Raw}, PrivateKey: serverKey}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	configFile := filepath.Join(dir, "ca.json")
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configFile, data, 0600))
	passwordFile := filepath.Join(dir, "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("issuer-validity-test-password"), 0600))
	return &issuerValidityCLI{now: now, root: root, issuer: issuer, oldIssuer: oldIssuer, issuerKey: mini.Signer, jwk: jwk,
		server: server, rootFile: rootFile, configFile: configFile, passwordFile: passwordFile}
}

func (f *issuerValidityCLI) signToken(t *testing.T, subject string) string {
	t.Helper()
	token, err := cautils.NewTokenGenerator(f.jwk.KeyID, "issuer-validity", f.server.URL+"/sign", "", time.Time{}, time.Time{}, f.jwk).SignToken(subject, []string{subject})
	require.NoError(t, err)
	return token
}

func (f *issuerValidityCLI) sshToken(t *testing.T, certType string) string {
	t.Helper()
	token, err := cautils.NewTokenGenerator(f.jwk.KeyID, "issuer-validity", f.server.URL+"/ssh/sign", "", time.Time{}, time.Time{}, f.jwk).
		SignSSHToken("ssh.example", certType, []string{"ssh.example"}, provisioner.TimeDuration{}, provisioner.TimeDuration{})
	require.NoError(t, err)
	return token
}

func (f *issuerValidityCLI) offlineFlags() []string {
	return []string{"--offline", "--ca-config", f.configFile, "--provisioner", "issuer-validity", "--provisioner-password-file", f.passwordFile}
}

func (f *issuerValidityCLI) run(t *testing.T, home string, args ...string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args = append(args, "--ca-url", f.server.URL, "--root", f.rootFile)
	cmd := exec.CommandContext(ctx, "step", args...)
	cmd.Env = append(os.Environ(), "STEPPATH="+home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (f *issuerValidityCLI) assertLeaf(t *testing.T, path string, expiry time.Time) *x509.Certificate {
	t.Helper()
	bundle, err := pemutil.ReadCertificateBundle(path)
	require.NoError(t, err)
	leaf := bundle[0]
	require.Equal(t, expiry, leaf.NotAfter)
	require.NoError(t, leaf.CheckSignatureFrom(f.issuer))
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(f.root)
	intermediates.AddCert(f.issuer)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: f.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err)
	return leaf
}

func (f *issuerValidityCLI) oldCredential(t *testing.T, notBefore, notAfter time.Time) (string, string, *x509.Certificate) {
	t.Helper()
	// Issue a genuine provisioner-bearing leaf with the old, longer-lived
	// issuer, then use it against the same-key replacement issuer.
	pub := f.jwk.Public()
	cfg := &config.Config{DNSNames: []string{"127.0.0.1"}, AuthorityConfig: &config.AuthConfig{
		DisableIssuedAtCheck: true, Backdate: &provisioner.Duration{},
		Provisioners: provisioner.List{&provisioner.JWK{Type: "JWK", Name: "issuer-validity", Key: &pub, Claims: &provisioner.Claims{
			MaxTLSDur: &provisioner.Duration{Duration: 168 * time.Hour},
		}}},
	}}
	auth, err := authority.NewEmbedded(authority.WithConfig(cfg), authority.WithX509RootCerts(f.root), authority.WithX509Signer(f.oldIssuer, f.issuerKey), authority.WithQuietInit())
	require.NoError(t, err)
	defer auth.Shutdown()
	ott, err := cautils.NewTokenGenerator(f.jwk.KeyID, "issuer-validity", "https://127.0.0.1/sign", "", time.Time{}, time.Time{}, f.jwk).SignToken("native.example", []string{"native.example"})
	require.NoError(t, err)
	req, key, err := ca.CreateSignRequest(ott)
	require.NoError(t, err)
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	ctx = apiv1.WithCertificateWarningHandler(ctx, func(w apiv1.CertificateWarning) { t.Fatalf("unexpected old-issuer warning: %s", w.Code) })
	opts, err := auth.Authorize(ctx, ott)
	require.NoError(t, err)
	chain, err := auth.SignWithContext(ctx, req.CsrPEM.CertificateRequest, provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(notBefore), NotAfter: provisioner.NewTimeDuration(notAfter),
	}, opts...)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "old.crt"), filepath.Join(dir, "old.key")
	var bundle []byte
	for _, cert := range chain {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	require.NoError(t, os.WriteFile(certFile, bundle, 0600))
	_, err = pemutil.Serialize(key, pemutil.ToFile(keyFile, 0600))
	require.NoError(t, err)
	return certFile, keyFile, chain[0]
}
