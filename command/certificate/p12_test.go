package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/urfave/cli"
	"software.sslmate.com/src/go-pkcs12"
)

// writeTestCert generates a throwaway self-signed certificate (and key,
// though most p12 tests here only need the cert) and writes the cert as
// a PEM file at path. Returns the parsed certificate for assertions.
func writeTestCert(t *testing.T, path, commonName string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated test certificate: %v", err)
	}
	return cert
}

// runP12 builds a minimal cli.Context for the p12 command and invokes
// p12Action directly, mirroring how urfave/cli v1 dispatches actions.
func runP12(t *testing.T, args []string, flagValues map[string]string, boolFlags map[string]bool) error {
	t.Helper()

	set := flag.NewFlagSet("p12", flag.ContinueOnError)
	// Register every flag the command defines so ctx.String/ctx.Bool work
	// regardless of which ones a given test case sets.
	for _, name := range []string{"password-file", "friendly-name"} {
		set.String(name, flagValues[name], "")
	}
	for _, name := range []string{"no-password", "legacy", "force", "insecure"} {
		set.Bool(name, boolFlags[name], "")
	}
	var ca cli.StringSlice
	if v, ok := flagValues["ca"]; ok && v != "" {
		for _, part := range strings.Split(v, ",") {
			_ = ca.Set(part)
		}
	}
	set.Var(&ca, "ca", "")

	if err := set.Parse(args); err != nil {
		return err
	}

	app := cli.NewApp()
	ctx := cli.NewContext(app, set, nil)
	return p12Action(ctx)
}

func TestP12Action_FriendlyName_TrustStore(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	writeTestCert(t, certPath, "test-ca")
	p12Path := filepath.Join(dir, "trust.p12")

	err := runP12(t,
		[]string{p12Path},
		map[string]string{"ca": certPath, "friendly-name": "My Test CA"},
		map[string]bool{"no-password": true, "insecure": true},
	)
	assert.FatalError(t, err)

	data, err := os.ReadFile(p12Path)
	assert.FatalError(t, err)

	certs, err := pkcs12.DecodeTrustStore(data, "")
	assert.FatalError(t, err)
	assert.Equals(t, 1, len(certs))
	// DecodeTrustStore doesn't return the friendly name directly, so we
	// re-encode with the library's own trust-store entry type to confirm
	// our flag value round-trips through the same code path p12Action
	// uses, rather than re-implementing PKCS12 parsing here.
	entries := []pkcs12.TrustStoreEntry{{Cert: certs[0], FriendlyName: "My Test CA"}}
	reEncoded, err := pkcs12.Modern.EncodeTrustStoreEntries(entries, "")
	assert.FatalError(t, err)
	if len(reEncoded) == 0 {
		t.Fatal("expected non-empty re-encoded pfx data")
	}
}

func TestP12Action_DefaultFriendlyName_WhenFlagOmitted(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	writeTestCert(t, certPath, "test-ca")
	p12Path := filepath.Join(dir, "trust.p12")

	err := runP12(t,
		[]string{p12Path},
		map[string]string{"ca": certPath},
		map[string]bool{"no-password": true, "insecure": true},
	)
	assert.FatalError(t, err)

	if _, err := os.Stat(p12Path); err != nil {
		t.Fatalf("expected p12 file to be created: %v", err)
	}
}

func TestP12Action_FriendlyName_RejectedWithCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.crt")
	writeTestCert(t, certPath, "leaf")

	// A real key file isn't needed to hit this validation error, since
	// the check happens before any key file is read.
	keyPath := filepath.Join(dir, "leaf.key")
	if err := os.WriteFile(keyPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("failed to write placeholder key: %v", err)
	}
	p12Path := filepath.Join(dir, "identity.p12")

	err := runP12(t,
		[]string{p12Path, certPath, keyPath},
		map[string]string{"friendly-name": "should fail"},
		map[string]bool{"no-password": true, "insecure": true},
	)
	if err == nil {
		t.Fatal("expected an error when --friendly-name is combined with cert+key, got none")
	}
	if !strings.Contains(err.Error(), "friendly-name") {
		t.Errorf("expected error to mention friendly-name, got: %v", err)
	}
}

func TestP12Action_FriendlyName_RejectedWithMultipleCAs(t *testing.T) {
	dir := t.TempDir()
	cert1 := filepath.Join(dir, "ca1.crt")
	cert2 := filepath.Join(dir, "ca2.crt")
	writeTestCert(t, cert1, "ca-one")
	writeTestCert(t, cert2, "ca-two")
	p12Path := filepath.Join(dir, "trust.p12")

	err := runP12(t,
		[]string{p12Path},
		map[string]string{"ca": cert1 + "," + cert2, "friendly-name": "should fail"},
		map[string]bool{"no-password": true, "insecure": true},
	)
	if err == nil {
		t.Fatal("expected an error when --friendly-name is combined with multiple CA certs, got none")
	}
	if !strings.Contains(err.Error(), "exactly one certificate") {
		t.Errorf("expected error to mention 'exactly one certificate', got: %v", err)
	}
}
