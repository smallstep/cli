package renewer

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
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
	mtls      bool
}

func New(client caclient.CaClient, tr *http.Transport, key crypto.PrivateKey, offline bool, cert tls.Certificate, caURL *url.URL, useMTLS bool) *Renewer {
	return &Renewer{
		client:    client,
		transport: tr,
		key:       key,
		offline:   offline,
		cert:      cert,
		caURL:     caURL,
		mtls:      useMTLS,
	}
}

func (r *Renewer) Renew(outFile string) (resp *api.SignResponse, err error) {
	if !r.mtls || time.Now().After(r.cert.Leaf.NotAfter) {
		resp, err = r.RenewWithToken(r.cert)
	} else {
		resp, err = r.client.Renew(r.transport)
	}
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

// RenewWithToken creates an authorization token with the given certificate and
// attempts to renew the given certificate. It can be used to renew expired
// certificates.
func (r *Renewer) RenewWithToken(cert tls.Certificate) (*api.SignResponse, error) {
	claims, err := token.NewClaims(
		token.WithAudience(r.caURL.ResolveReference(&url.URL{Path: "/renew"}).String()),
		token.WithIssuer("step-ca-client/1.0"),
		token.WithSubject(cert.Leaf.Subject.CommonName),
	)
	if err != nil {
		return nil, errors.Wrap(err, "error creating authorization token")
	}
	var x5c []string
	for _, b := range cert.Certificate {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(b))
	}
	if claims.ExtraHeaders == nil {
		claims.ExtraHeaders = make(map[string]interface{})
	}
	claims.ExtraHeaders[jose.X5cInsecureKey] = x5c

	tok, err := claims.Sign("", cert.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error signing authorization token")
	}

	// Remove existing certificate from the transport. And close keep-alive
	// connections. When daemon is used we don't want to re-use the connection
	// that did not include a certificate.
	r.transport.TLSClientConfig.Certificates = nil
	defer r.transport.CloseIdleConnections()

	return r.client.RenewWithToken(tok)
}
