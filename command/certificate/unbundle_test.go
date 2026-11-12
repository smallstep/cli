package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/urfave/cli"
	"go.step.sm/crypto/pemutil"
)

func testCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	assert.FatalError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func runUnbundle(t *testing.T, crtFile, out string, leaf, intermediate bool) error {
	t.Helper()
	set := flag.NewFlagSet("unbundle", 0)
	set.Bool("leaf", false, "")
	set.Bool("intermediate", false, "")
	set.String("out", "", "")
	set.Bool("force", false, "")

	args := []string{}
	if leaf {
		args = append(args, "--leaf")
	}
	if intermediate {
		args = append(args, "--intermediate")
	}
	if out != "" {
		args = append(args, "--out", out)
	}
	args = append(args, crtFile)
	assert.FatalError(t, set.Parse(args))

	return unbundleAction(cli.NewContext(&cli.App{}, set, nil))
}

func TestUnbundle(t *testing.T) {
	dir := t.TempDir()

	leafPEM := testCertPEM(t, "leaf.example.com")
	interPEM := testCertPEM(t, "intermediate.example.com")

	bundle := append(append([]byte{}, leafPEM...), interPEM...)
	bundleFile := filepath.Join(dir, "bundle.crt")
	assert.FatalError(t, os.WriteFile(bundleFile, bundle, 0o600))

	singleFile := filepath.Join(dir, "single.crt")
	assert.FatalError(t, os.WriteFile(singleFile, leafPEM, 0o600))

	badFile := filepath.Join(dir, "bad.crt")
	assert.FatalError(t, os.WriteFile(badFile, []byte("not a certificate"), 0o600))

	t.Run("leaf from bundle", func(t *testing.T) {
		out := filepath.Join(dir, "leaf-out.crt")
		assert.FatalError(t, runUnbundle(t, bundleFile, out, true, false))
		certs := readBundle(t, out)
		assert.Equals(t, 1, len(certs))
		assert.Equals(t, "leaf.example.com", certs[0].Subject.CommonName)
	})

	t.Run("intermediate from bundle", func(t *testing.T) {
		out := filepath.Join(dir, "inter-out.crt")
		assert.FatalError(t, runUnbundle(t, bundleFile, out, false, true))
		certs := readBundle(t, out)
		assert.Equals(t, 1, len(certs))
		assert.Equals(t, "intermediate.example.com", certs[0].Subject.CommonName)
	})

	t.Run("leaf from single cert", func(t *testing.T) {
		out := filepath.Join(dir, "single-out.crt")
		assert.FatalError(t, runUnbundle(t, singleFile, out, true, false))
		certs := readBundle(t, out)
		assert.Equals(t, 1, len(certs))
		assert.Equals(t, "leaf.example.com", certs[0].Subject.CommonName)
	})

	t.Run("intermediate from single cert errors", func(t *testing.T) {
		err := runUnbundle(t, singleFile, filepath.Join(dir, "nope.crt"), false, true)
		assert.Error(t, err)
	})

	t.Run("bad input errors", func(t *testing.T) {
		err := runUnbundle(t, badFile, filepath.Join(dir, "nope2.crt"), true, false)
		assert.Error(t, err)
	})

	t.Run("no selector errors", func(t *testing.T) {
		err := runUnbundle(t, bundleFile, "", false, false)
		assert.Error(t, err)
	})

	t.Run("both selectors error", func(t *testing.T) {
		err := runUnbundle(t, bundleFile, "", true, true)
		assert.Error(t, err)
	})
}

func readBundle(t *testing.T, file string) []*x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(file)
	assert.FatalError(t, err)
	certs, err := pemutil.ParseCertificateBundle(b)
	assert.FatalError(t, err)
	return certs
}
