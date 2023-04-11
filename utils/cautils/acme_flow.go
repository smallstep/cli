package cautils

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"
)

// ACMECreateCertFlow performs an ACME transaction to get a new certificate.
func ACMECreateCertFlow(ctx *cli.Context, provisionerName string) error {
	args := ctx.Args()
	subject := args.Get(0)
	certFile, keyFile := args.Get(1), args.Get(2)

	af, err := newACMEFlow(ctx, withSubjectSANs(subject, ctx.StringSlice("san")),
		withProvisionerName(provisionerName))
	if err != nil {
		return err
	}
	certs, err := af.GetCertificate()
	if err != nil {
		return err
	}
	if err := writeCert(certs, certFile); err != nil {
		return err
	}
	ui.PrintSelected("Certificate", certFile)

	// We won't have a private key with attestation certificates
	if af.priv != nil {
		_, err = pemutil.Serialize(af.priv, pemutil.ToFile(keyFile, 0600))
		if err != nil {
			return errors.WithStack(err)
		}
		ui.PrintSelected("Private Key", keyFile)
	} else if v := ctx.String("attestation-uri"); v != "" {
		// TODO: refactor this to be cleaner by passing the TPM and/or key around
		// instead of creating a new instance.
		if af.tpmSigner != nil {
			tpmStorageDirectory := ctx.String("tpm-storage-directory")
			t, err := tpm.New(tpm.WithStore(tpmstorage.NewDirstore(tpmStorageDirectory)))
			if err != nil {
				return fmt.Errorf("failed initializing TPM: %w", err)
			}
			keyName, err := parseTPMAttestationURI(ctx.String("attestation-uri"))
			if err != nil {
				return fmt.Errorf("failed parsing --attestation-uri: %w", err)
			}
			ctx := tpm.NewContext(context.Background(), t)
			key, err := t.GetKey(ctx, keyName)
			if err != nil {
				return fmt.Errorf("failed getting TPM key: %w", err)
			}
			if err = key.SetCertificateChain(ctx, certs); err != nil {
				return fmt.Errorf("failed storing certificate with TPM key: %w", err)
			}
		}

		ui.PrintSelected("Private Key", v)
	}
	return nil
}

// ACMESignCSRFlow performs an ACME transaction using an existing CSR to get a
// new certificate.
func ACMESignCSRFlow(ctx *cli.Context, csr *x509.CertificateRequest, certFile, provisionerName string) error {
	af, err := newACMEFlow(ctx, withCSR(csr), withProvisionerName(provisionerName))
	if err != nil {
		return err
	}
	certs, err := af.GetCertificate()
	if err != nil {
		return err
	}
	if err := writeCert(certs, certFile); err != nil {
		return err
	}
	ui.PrintSelected("Certificate", certFile)
	return nil
}
