package cautils

import (
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/pemutil"
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
