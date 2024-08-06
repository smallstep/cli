package token

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	nebula "github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/ssh"
)

func TestOptions(t *testing.T) {
	empty := new(Claims)
	now := time.Now()
	c25519CACert, c25519CAKey := mustNebulaCurve25519CA(t)
	p256CACert, p256CAKey := mustNebulaP256CA(t)
	c25519Cert, c25519Signer := mustNebulaCurve25519Cert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, c25519CACert, c25519CAKey)
	p256Cert, p256Signer := mustNebulaP256Cert(t, "test.lan", mustNebulaIPNet(t, "10.1.0.1/16"), []string{"test"}, p256CACert, p256CAKey)

	tempDir := t.TempDir()
	c25519CACertFilename, c25519CACertData := serializeAndWriteNebulaCert(t, tempDir, c25519CACert)
	c25519CertFilename, c25519CertData := serializeAndWriteNebulaCert(t, tempDir, c25519Cert)
	p256CertFilename, p256CertData := serializeAndWriteNebulaCert(t, tempDir, p256Cert)

	p256ECDHSigner, err := p256Signer.ECDH()
	require.NoError(t, err)

	testCSR, err := pemutil.ReadCertificateRequest("testdata/test.csr")
	require.NoError(t, err)

	testSSH := mustReadSSHPublicKey(t, "testdata/ssh-key.pub")

	wrongNebulaContentsFilename := "testdata/ca.crt"

	emptyFile, err := os.CreateTemp(tempDir, "empty-file")
	require.NoError(t, err)
	emptyFile.Close()

	tests := []struct {
		name    string
		option  Options
		want    *Claims
		wantErr bool
	}{
		{"WithClaim ok", WithClaim("name", "foo"), &Claims{ExtraClaims: map[string]interface{}{"name": "foo"}}, false},
		{"WithClaim fail", WithClaim("", "foo"), empty, true},
		{"WithRootCA ok", WithRootCA("testdata/ca.crt"), &Claims{ExtraClaims: map[string]interface{}{"sha": "6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98"}}, false},
		{"WithRootCA fail", WithRootCA("not-exists"), empty, true},
		{"WithValidity ok", WithValidity(now, now.Add(5*time.Minute)), &Claims{Claims: jose.Claims{NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(5 * time.Minute))}}, false},
		{"WithRootCA expired", WithValidity(now, now.Add(-1*time.Second)), empty, true},
		{"WithRootCA long delay", WithValidity(now.Add(MaxValidityDelay+time.Minute), now.Add(MaxValidityDelay+10*time.Minute)), empty, true},
		{"WithRootCA min validity ok", WithValidity(now, now.Add(MinValidity)), &Claims{Claims: jose.Claims{NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(MinValidity))}}, false},
		{"WithRootCA min validity fail", WithValidity(now, now.Add(MinValidity-time.Second)), empty, true},
		{"WithRootCA max validity ok", WithValidity(now, now.Add(MaxValidity)), &Claims{Claims: jose.Claims{NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(MaxValidity))}}, false},
		{"WithRootCA max validity fail", WithValidity(now, now.Add(MaxValidity+time.Second)), empty, true},
		{"WithIssuer ok", WithIssuer("value"), &Claims{Claims: jose.Claims{Issuer: "value"}}, false},
		{"WithIssuer fail", WithIssuer(""), empty, true},
		{"WithSubject ok", WithSubject("value"), &Claims{Claims: jose.Claims{Subject: "value"}}, false},
		{"WithSubject fail", WithSubject(""), empty, true},
		{"WithAudience ok", WithAudience("value"), &Claims{Claims: jose.Claims{Audience: jose.Audience{"value"}}}, false},
		{"WithAudience fail", WithAudience(""), empty, true},
		{"WithJWTID ok", WithJWTID("value"), &Claims{Claims: jose.Claims{ID: "value"}}, false},
		{"WithJWTID fail", WithJWTID(""), empty, true},
		{"WithKid ok", WithKid("value"), &Claims{ExtraHeaders: map[string]interface{}{"kid": "value"}}, false},
		{"WithKid fail", WithKid(""), empty, true},
		{"WithSHA ok", WithSHA("6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98"), &Claims{ExtraClaims: map[string]interface{}{"sha": "6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98"}}, false},
		{"WithNebulaCurve25519Cert ok", WithNebulaCert(c25519CertFilename, c25519Signer), &Claims{ExtraHeaders: map[string]interface{}{"nebula": c25519CertData}}, false},
		{"WithNebulaCurve25519CACert ok", WithNebulaCert(c25519CACertFilename, c25519CAKey), &Claims{ExtraHeaders: map[string]interface{}{"nebula": c25519CACertData}}, false},
		{"WithNebulaCurve25519Cert and key as bytes ok", WithNebulaCert(c25519CertFilename, []byte(c25519Signer)), &Claims{ExtraHeaders: map[string]interface{}{"nebula": c25519CertData}}, false},
		{"WithNebulaP256Cert ok", WithNebulaCert(p256CertFilename, p256Signer), &Claims{ExtraHeaders: map[string]interface{}{"nebula": p256CertData}}, false},
		{"WithNebulaP256Cert as ECDH signer ok", WithNebulaCert(p256CertFilename, p256ECDHSigner), &Claims{ExtraHeaders: map[string]interface{}{"nebula": p256CertData}}, false},
		{"WithNebulaCurve25519Cert non existing file fail", WithNebulaCert(filepath.Join(tempDir, "does-not-exist"), nil), empty, true},
		{"WithNebulaCurve25519Cert wrong contents fail", WithNebulaCert(wrongNebulaContentsFilename, nil), empty, true},
		{"WithNebulaCurve25519Cert empty file fail", WithNebulaCert(emptyFile.Name(), nil), empty, true},
		{"WithNebulaCurve25519Cert invalid content fail", WithNebulaCert(c25519CertFilename, nil), empty, true},
		{"WithNebulaCurve25519Cert mismatching key fail", WithNebulaCert(c25519CertFilename, p256Signer), empty, true},
		{"WithConfirmationFingerprint ok", WithConfirmationFingerprint("my-kid"), &Claims{ExtraClaims: map[string]any{"cnf": map[string]string{"x5rt#S256": "my-kid"}}}, false},
		{"WithFingerprint csr ok", WithFingerprint(testCSR), &Claims{ExtraClaims: map[string]any{"cnf": map[string]string{"x5rt#S256": "ak6j6CwuZbd_mOQ-pNOUwhpmtSN0mY0xrLvaQL4J5l8"}}}, false},
		{"WithFingerprint ssh ok", WithFingerprint(testSSH), &Claims{ExtraClaims: map[string]any{"cnf": map[string]string{"x5rt#S256": "hpTQOoB7fIRxTp-FhXCIm94mGBv7_dzr_5SxLn1Pnwk"}}}, false},
		{"WithFingerprint fail", WithFingerprint("unexpected type"), empty, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := new(Claims)
			err := tt.option(claim)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, claim)
		})
	}
}

func mustReadSSHPublicKey(t *testing.T, filename string) ssh.PublicKey {
	t.Helper()

	b, err := os.ReadFile(filename)
	require.NoError(t, err)

	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	require.NoError(t, err)

	return pub
}

func serializeAndWriteNebulaCert(t *testing.T, tempDir string, cert *nebula.NebulaCertificate) (string, []byte) {
	file, err := os.CreateTemp(tempDir, "nebula-test-cert-*")
	require.NoError(t, err)
	defer file.Close()
	pem, err := cert.MarshalToPEM()
	require.NoError(t, err)
	data, err := cert.Marshal()
	require.NoError(t, err)
	_, err = file.Write(pem)
	require.NoError(t, err)
	return file.Name(), data
}

func mustNebulaIPNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	require.NoError(t, err)

	if ip = ip.To4(); ip == nil {
		require.Failf(t, "nebula only supports ipv4, have %s", s)
	}

	ipNet.IP = ip
	return ipNet
}

func mustNebulaCurve25519CA(t *testing.T) (*nebula.NebulaCertificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	nc := &nebula.NebulaCertificate{
		Details: nebula.NebulaCertificateDetails{
			Name:   "TestCA",
			Groups: []string{"test"},
			Ips: []*net.IPNet{
				mustNebulaIPNet(t, "10.1.0.0/16"),
			},
			Subnets:   []*net.IPNet{},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(10 * time.Minute),
			PublicKey: pub,
			IsCA:      true,
			Curve:     nebula.Curve_CURVE25519,
		},
	}

	require.NoError(t, nc.Sign(nebula.Curve_CURVE25519, priv))

	return nc, priv
}

func mustNebulaP256CA(t *testing.T) (*nebula.NebulaCertificate, *ecdh.PrivateKey) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	nc := &nebula.NebulaCertificate{
		Details: nebula.NebulaCertificateDetails{
			Name:   "TestCA",
			Groups: []string{"test"},
			Ips: []*net.IPNet{
				mustNebulaIPNet(t, "10.1.0.0/16"),
			},
			Subnets:   []*net.IPNet{},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(10 * time.Minute),
			PublicKey: priv.PublicKey().Bytes(),
			IsCA:      true,
			Curve:     nebula.Curve_P256,
		},
	}

	require.NoError(t, nc.Sign(nebula.Curve_P256, priv.Bytes()))

	return nc, priv
}

func mustNebulaCurve25519Cert(t *testing.T, name string, ipNet *net.IPNet, groups []string, ca *nebula.NebulaCertificate, signer ed25519.PrivateKey) (*nebula.NebulaCertificate, x25519.PrivateKey) {
	t.Helper()

	pub, priv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuer, err := ca.Sha256Sum()
	require.NoError(t, err)

	invertedGroups := make(map[string]struct{}, len(groups))
	for _, name := range groups {
		invertedGroups[name] = struct{}{}
	}

	key := []byte(signer)
	curve := nebula.Curve_CURVE25519

	t1 := time.Now().Truncate(time.Second)
	nc := &nebula.NebulaCertificate{
		Details: nebula.NebulaCertificateDetails{
			Name:           name,
			Ips:            []*net.IPNet{ipNet},
			Subnets:        []*net.IPNet{},
			Groups:         groups,
			NotBefore:      t1,
			NotAfter:       t1.Add(5 * time.Minute),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: invertedGroups,
			Curve:          curve,
		},
	}

	require.NoError(t, nc.Sign(curve, key))

	return nc, priv
}

func mustNebulaP256Cert(t *testing.T, name string, ipNet *net.IPNet, groups []string, ca *nebula.NebulaCertificate, signer *ecdh.PrivateKey) (*nebula.NebulaCertificate, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer, err := ca.Sha256Sum()
	require.NoError(t, err)

	invertedGroups := make(map[string]struct{}, len(groups))
	for _, name := range groups {
		invertedGroups[name] = struct{}{}
	}

	key := signer.Bytes()
	curve := nebula.Curve_P256

	pk, err := priv.ECDH()
	require.NoError(t, err)

	t1 := time.Now().Truncate(time.Second)
	nc := &nebula.NebulaCertificate{
		Details: nebula.NebulaCertificateDetails{
			Name:           name,
			Ips:            []*net.IPNet{ipNet},
			Subnets:        []*net.IPNet{},
			Groups:         groups,
			NotBefore:      t1,
			NotAfter:       t1.Add(5 * time.Minute),
			PublicKey:      pk.PublicKey().Bytes(),
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: invertedGroups,
			Curve:          curve,
		},
	}

	require.NoError(t, nc.Sign(curve, key))

	return nc, priv
}
