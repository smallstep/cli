package integration

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
)

func TestCertificateSignCommand(t *testing.T) {
	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, signer)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err)
	caSigner, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test-ca"},
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		MaxPathLen:            1,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caSigner.Public(), caSigner)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/certificate/sign.txtar"},
		Setup: func(e *testscript.Env) error {
			_, err := pemutil.Serialize(csr, pemutil.WithFilename(filepath.Join(e.Cd, "test.csr")))
			require.NoError(t, err)
			_, err = pemutil.Serialize(caCert, pemutil.WithFilename(filepath.Join(e.Cd, "cacert.pem")))
			require.NoError(t, err)
			_, err = pemutil.Serialize(caSigner, pemutil.WithFilename(filepath.Join(e.Cd, "cakey.pem")))
			require.NoError(t, err)

			return nil
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"check_certificate": checkCertificate,
		},
	})

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/certificate/sign-bad-csr.txtar"},
		Setup: func(e *testscript.Env) error {
			err := os.WriteFile(filepath.Join(e.Cd, "bad.csr"), []byte("bogus"), 0644)
			require.NoError(t, err)
			_, err = pemutil.Serialize(caCert, pemutil.WithFilename(filepath.Join(e.Cd, "cacert.pem")))
			require.NoError(t, err)
			_, err = pemutil.Serialize(caSigner, pemutil.WithFilename(filepath.Join(e.Cd, "cakey.pem")))
			require.NoError(t, err)

			return nil
		},
	})
}

func TestCertificateVerifyCommand(t *testing.T) {
	ca, err := minica.New(minica.WithName("TestCertificateVerify"))
	require.NoError(t, err)
	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "test-cert"},
		PublicKey: signer.Public(),
	}
	crt, err := ca.Sign(tmpl)
	require.NoError(t, err)

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/certificate/verify.txtar"},
		Setup: func(e *testscript.Env) error {
			_, err := pemutil.Serialize(crt, pemutil.WithFilename(filepath.Join(e.Cd, "test.crt")))
			require.NoError(t, err)
			_, err = pemutil.Serialize(ca.Intermediate, pemutil.WithFilename(filepath.Join(e.Cd, "intermediate.pem")))
			require.NoError(t, err)

			return nil
		},
	})

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/certificate/verify-bad-pem.txtar"},
		Setup: func(e *testscript.Env) error {
			err := os.WriteFile(filepath.Join(e.Cd, "bad.pem"), []byte("bogus"), 0644)
			require.NoError(t, err)

			return nil
		},
	})
}

func TestCertificateFingerprintCommand(t *testing.T) {
	b, err := os.ReadFile("./testdata/intermediate_ca.crt")
	require.NoError(t, err)

	testscript.Run(t, testscript.Params{
		Files: []string{"testdata/certificate/fingerprint.txtar"},
		Setup: func(e *testscript.Env) error {
			err := os.WriteFile(filepath.Join(e.Cd, "intermediate_ca.crt"), b, 0600)
			require.NoError(t, err)

			return nil
		},
	})
}

func checkCertificate(ts *testscript.TestScript, neg bool, args []string) {
	contents := ts.ReadFile("stdout") // directly reads from stdout of the previously executed command
	bundle, err := pemutil.ParseCertificateBundle([]byte(contents))
	ts.Check(err)

	if len(bundle) != 1 {
		ts.Fatalf("expected 1 certificate; got %d", len(bundle))
	}
}
