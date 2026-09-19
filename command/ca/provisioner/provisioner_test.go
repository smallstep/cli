package provisioner

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	nebula "github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func TestReadNebulaRoots(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		tempDir := t.TempDir()
		ca, _ := mustNebulaCurve25519CA(t)
		file, _ := serializeAndWriteNebulaCert(t, tempDir, ca)

		roots, err := readNebulaRoots(file)
		assert.NoError(t, err)
		assert.Len(t, roots, 1)
	})

	t.Run("fail/reading", func(t *testing.T) {
		roots, err := readNebulaRoots("non-existing-file")
		assert.Error(t, err)
		assert.Empty(t, roots)
	})

	t.Run("fail/invalid-pem", func(t *testing.T) {
		tempDir := t.TempDir()

		file, err := os.CreateTemp(tempDir, "nebula-test-cert-*")
		require.NoError(t, err)
		defer file.Close()

		_, err = file.Write([]byte{0})
		require.NoError(t, err)

		roots, err := readNebulaRoots(file.Name())
		assert.Error(t, err)
		assert.Empty(t, roots)
	})

	t.Run("fail/no-certificates", func(t *testing.T) {
		tempDir := t.TempDir()

		file, err := os.CreateTemp(tempDir, "nebula-test-cert-*")
		require.NoError(t, err)
		defer file.Close()

		roots, err := readNebulaRoots(file.Name())
		assert.Error(t, err)
		assert.Empty(t, roots)
	})
}

func mustNebulaCurve25519CA(t *testing.T) (nebula.Certificate, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tbs := &nebula.TBSCertificate{
		Version:   nebula.Version1,
		Name:      "TestCA",
		Groups:    []string{"test"},
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(10 * time.Minute),
		PublicKey: pub,
		IsCA:      true,
		Curve:     nebula.Curve_CURVE25519,
	}
	nc, err := tbs.Sign(nil, nebula.Curve_CURVE25519, priv)
	require.NoError(t, err)

	return nc, priv
}

func serializeAndWriteNebulaCert(t *testing.T, tempDir string, cert nebula.Certificate) (string, []byte) {
	file, err := os.CreateTemp(tempDir, "nebula-test-cert-*")
	require.NoError(t, err)
	defer file.Close()

	pem, err := cert.MarshalPEM()
	require.NoError(t, err)
	data, err := cert.Marshal()
	require.NoError(t, err)
	_, err = file.Write(pem)
	require.NoError(t, err)

	return file.Name(), data
}

func TestNewCRUDClient_CaConfigWithoutCaURL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "ca.json")
	// Paths need not exist: SkipValidation is set before authority.New.
	cfg := fmt.Sprintf(`{
  "root": %q,
  "crt": %q,
  "key": %q,
  "address": ":9000",
  "dnsNames": ["localhost"],
  "authority": {
    "provisioners": []
  }
}
`, filepath.Join(dir, "root.crt"), filepath.Join(dir, "intermediate.crt"), filepath.Join(dir, "intermediate.key"))
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfg), 0o600))

	app := cli.NewApp()
	set := flag.NewFlagSet("test", 0)
	_ = set.String("ca-url", "", "")
	_ = set.String("root", "", "")
	_ = set.String("ca-config", cfgFile, "")
	ctx := cli.NewContext(app, set, nil)

	client, err := newCRUDClient(ctx, cfgFile)
	require.NoError(t, err)
	require.NotNil(t, client)
	_, ok := client.(*caConfigClient)
	require.True(t, ok, "expected local caConfigClient when --ca-config exists and --ca-url is unset")
}

func TestNewCRUDClient_MissingCaURLWithoutConfig(t *testing.T) {
	t.Parallel()

	app := cli.NewApp()
	set := flag.NewFlagSet("test", 0)
	_ = set.String("ca-url", "", "")
	_ = set.String("root", "", "")
	ctx := cli.NewContext(app, set, nil)

	client, err := newCRUDClient(ctx, "")
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "ca-url")
}
