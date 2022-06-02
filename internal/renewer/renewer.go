package renewer

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/utils"
	caclient "github.com/smallstep/cli/utils/cautils/client"
	"go.step.sm/cli-utils/errs"
)

type Renewer struct {
	client    caclient.CaClient
	transport *http.Transport
	key       crypto.PrivateKey
	offline   bool
	cert      tls.Certificate
	caURL     *url.URL
}

func New(client caclient.CaClient, tr *http.Transport, key crypto.PrivateKey, offline bool, cert tls.Certificate, caURL *url.URL) *Renewer {
	return &Renewer{
		client:    client,
		transport: tr,
		key:       key,
		offline:   offline,
		cert:      cert,
		caURL:     caURL,
	}
}

func (r *Renewer) Renew(outFile string) (*api.SignResponse, error) {
	resp, err := r.client.Renew(r.transport)
	if err != nil {
		return nil, errors.Wrap(err, "error renewing certificate")
	}

	if resp.CertChainPEM == nil || len(resp.CertChainPEM) == 0 {
		resp.CertChainPEM = []api.Certificate{resp.ServerPEM, resp.CaPEM}
	}
	var data []byte
	for _, certPEM := range resp.CertChainPEM {
		pemblk, err := pemutil.Serialize(certPEM.Certificate)
		if err != nil {
			return nil, errors.Wrap(err, "error serializing certificate PEM")
		}
		data = append(data, pem.EncodeToMemory(pemblk)...)
	}
	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return nil, errs.FileError(err, outFile)
	}

	return resp, nil
}

func (r *Renewer) Rekey(priv interface{}, outCert, outKey string, writePrivateKey bool) (*api.SignResponse, error) {
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Rekey(&api.RekeyRequest{CsrPEM: api.NewCertificateRequest(csr)}, r.transport)
	if err != nil {
		return nil, errors.Wrap(err, "error rekeying certificate")
	}
	if resp.CertChainPEM == nil || len(resp.CertChainPEM) == 0 {
		resp.CertChainPEM = []api.Certificate{resp.ServerPEM, resp.CaPEM}
	}
	var data []byte
	for _, certPEM := range resp.CertChainPEM {
		pemblk, err := pemutil.Serialize(certPEM.Certificate)
		if err != nil {
			return nil, errors.Wrap(err, "error serializing certificate PEM")
		}
		data = append(data, pem.EncodeToMemory(pemblk)...)
	}
	if err := utils.WriteFile(outCert, data, 0600); err != nil {
		return nil, errs.FileError(err, outCert)
	}
	if writePrivateKey {
		_, err = pemutil.Serialize(priv, pemutil.ToFile(outKey, 0600))
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// RenewAndPrepareNext renews the cert and prepares the cert for it's next renewal.
// NOTE: this function logs each time the certificate is successfully renewed.
func (r *Renewer) RenewAndPrepareNext(outFile string, expiresIn, renewPeriod time.Duration) (time.Duration, error) {
	const durationOnErrors = 1 * time.Minute
	Info := log.New(os.Stdout, "INFO: ", log.LstdFlags)

	resp, err := r.Renew(outFile)
	if err != nil {
		return durationOnErrors, err
	}

	x509Chain, err := pemutil.ReadCertificateBundle(outFile)
	if err != nil {
		return durationOnErrors, errs.Wrap(err, "error reading certificate chain")
	}
	x509ChainBytes := make([][]byte, len(x509Chain))
	for i, c := range x509Chain {
		x509ChainBytes[i] = c.Raw
	}

	cert := tls.Certificate{
		Certificate: x509ChainBytes,
		PrivateKey:  r.key,
		Leaf:        x509Chain[0],
	}
	if len(cert.Certificate) == 0 {
		return durationOnErrors, errors.New("error loading certificate: certificate chain is empty")
	}

	// Prepare next transport
	r.transport.TLSClientConfig.Certificates = []tls.Certificate{cert}

	// Get next renew duration
	next := utils.NextRenewDuration(resp.ServerPEM.Certificate, expiresIn, renewPeriod)
	Info.Printf("%s certificate renewed, next in %s", resp.ServerPEM.Certificate.Subject.CommonName, next.Round(time.Second))
	return next, nil
}
