package cautils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"
)

func doTPMAttestation(clictx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string, af *acmeFlow) error {
	tpmStorageDirectory := clictx.String("tpm-storage-directory")
	t, err := tpm.New(tpm.WithStore(tpmstorage.NewDirstore(tpmStorageDirectory)))
	if err != nil {
		return fmt.Errorf("failed initializing TPM: %w", err)
	}

	tpmAttestationCABaseURL := clictx.String("attestation-ca-url")
	if tpmAttestationCABaseURL == "" {
		return fmt.Errorf("flag %q cannot be empty", "--attestation-ca-url")
	}

	tpmAttestationCARootFile := clictx.String("attestation-ca-root")

	attestationURI := clictx.String("attestation-uri")
	keyName, err := parseTPMAttestationURI(attestationURI)
	if err != nil {
		return fmt.Errorf("failed parsing --attestation-uri: %w", err)
	}

	ui.Printf("Using Device Attestation challenge to validate %q", identifier)
	ui.Printf(" .") // Indicates passage of time.

	ctx := tpm.NewContext(context.Background(), t)
	info, err := t.Info(ctx)
	if err != nil {
		return fmt.Errorf("failed retrieving TPM info: %w", err)
	}

	// TODO(hs): remove this from the standard output, unless debugging/verbose logging?
	ui.Printf("\nTPM INFO:")
	ui.Printf("\nversion: %s", info.Version)
	ui.Printf("\ninterface: %s", info.Interface)
	ui.Printf("\nmanufacturer: %s", info.Manufacturer)
	ui.Printf("\nvendor info: %s", info.VendorInfo)
	ui.Printf("\nfirmware version: %s", info.FirmwareVersion)

	atc, err := newAttestationClient(tpmAttestationCABaseURL, withRootsFile(tpmAttestationCARootFile), withInsecure()) // TODO(hs): remove `withInsecure`; convenience option
	if err != nil {
		return fmt.Errorf("failed creating attestation client: %w", err)
	}

	ak, err := getAK(ctx, t, atc)
	if err != nil {
		return fmt.Errorf("failed getting AK: %w", err)
	}

	// Generate the key authorization digest
	data, err := keyAuthDigest(ac.Key, ch.Token)
	if err != nil {
		return fmt.Errorf("failed creating key authorization: %w", err)
	}

	config := tpm.AttestKeyConfig{
		Algorithm:      "RSA", // TODO(hs): should come from flag/default input
		Size:           2048,  // TODO(hs): should come from flag/default input
		QualifyingData: data,
	}
	attestedKey, err := t.AttestKey(ctx, ak.Name(), keyName, config)
	if err != nil {
		return fmt.Errorf("failed creating new key attested by AK %q: %w", ak.Name(), err)
	}

	// Generate the WebAuthn attestation statement.
	attStmt, err := attestationStatement(ctx, attestedKey, ak.CertificateChain())
	if err != nil {
		return fmt.Errorf("failed creating attestation statement: %w", err)
	}

	challengeBody := struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attStmt),
	}

	payload, err := json.Marshal(challengeBody)
	if err != nil {
		return fmt.Errorf("failed marshaling challenge body: %w", err)
	}

	if err := ac.ValidateWithPayload(ch.URL, payload); err != nil {
		ui.Printf(" Error!\n\n")
		return fmt.Errorf("failed validating ACME Challenge at %q: %w", ch.URL, err)
	}

	durationBetweenAttempts := 2 * time.Second
	if err := getChallengeStatus(ac, ch, durationBetweenAttempts); err != nil {
		ui.Printf(" Error!\n\n")
		return err
	}

	ui.Printf(" done!\n")

	// passing the TPM key to the ACME flow, so that it can be used as a signer
	// TODO(hs): this is a bit of a hack that needs refactoring; should ideally behave similar to `step` format
	signer, err := attestedKey.Signer(ctx)
	if err != nil {
		return fmt.Errorf("failed getting signer for key %q", attestedKey.Name())
	}

	af.tpmSigner = signer

	return nil
}

// parseTPMAttestationURI parses attestation URIs for `tpmkms`.
func parseTPMAttestationURI(attestationURI string) (string, error) {
	if attestationURI == "" {
		return "", errors.New("attestation URI cannot be empty")
	}
	if !strings.HasPrefix(attestationURI, "tpmkms:") {
		return "", fmt.Errorf("%q does not start with tpmkms", attestationURI)
	}
	u, err := uri.Parse(attestationURI)
	if err != nil {
		return "", fmt.Errorf("failed parsing %q: %w", attestationURI, err)
	}
	var name string
	if name = u.Get("name"); name == "" {
		return "", fmt.Errorf("failed parsing %q: name is missing", attestationURI)
	}
	// TODO(hs): more properties for objects created/attested in TPM
	return name, nil
}

// getAK returns an AK suitable for attesting the identifier that is requested. The
// current behavior is to look for an AK backed by the TPM that has been issued a
// certificate that includes the EK public key ID as one of it URI SANs. The AK itself
// is identified by the hexadecimal representation of the EK public key.
func getAK(ctx context.Context, t *tpm.TPM, ac *attestationClient) (*tpm.AK, error) {
	eks, err := t.GetEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving TPM EKs: %w", err)
	}

	ekPublic := eks[0].Public()
	ekKeyID, err := generateKeyID(ekPublic)
	if err != nil {
		return nil, fmt.Errorf("failed getting EK public key ID: %w", err)
	}

	ekHexFingerprint, err := keyutil.EncodedFingerprint(ekPublic, keyutil.HexFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed creating EK fingerprint: %w", err)
	}

	// strip off "<hash>:"
	ekHexFingerprint = strings.Split(ekHexFingerprint, ":")[1]

	// look for an AK named after the EK hex fingerprint by default
	var ak *tpm.AK
	if ak, err = t.GetAK(ctx, ekHexFingerprint); err != nil { // TODO(hs): determine if we want this as the (current) default behavior
		// return early if an error occurred that doesn't indicate that the AK does not exist
		if !errors.Is(err, tpm.ErrNotFound) {
			return nil, fmt.Errorf("failed getting AK: %w", err)
		}
		// create a new AK if it wasn't found. We're using the identifier as the name
		// used for storing the AK for convenience.
		if ak, err = t.CreateAK(ctx, ekHexFingerprint); err != nil {
			return nil, fmt.Errorf("failed creating AK: %w", err)
		}
	}

	// check if a (valid) AK certificate (chain) is available. Perform attestation flow otherwise.
	akChain := ak.CertificateChain()
	if len(akChain) == 0 || !hasValidIdentity(ak, ekKeyID) {
		if akChain, err = ac.performAttestation(ctx, t, ak); err != nil {
			return nil, fmt.Errorf("failed performing AK attestation: %w", err)
		}
		if err := ak.SetCertificateChain(ctx, akChain); err != nil {
			return nil, fmt.Errorf("failed storing AK certificate chain: %w", err)
		}
	}

	// when a new certificate was issued for the AK, it is possible the
	// certificate that was issued doesn't include the expected and/or required
	// identity, so this is checked before continuing.
	if !hasValidIdentity(ak, ekKeyID) {
		return nil, fmt.Errorf("AK certificate (chain) not valid for %q", ekHexFingerprint) // TODO(hs): change logic for printing ekKeyID
	}

	// TODO(hs): perform precheck to verify the retrieved AK certificate chain
	// does belong to the TPM that's in use? Depending on how the certificate
	// was obtained and stored, it might've been altered somehow.
	// TODO(hs): support attestation flow with multiple Attestation CAs for a
	// single AK? Currently an AK is identified just by its name and can only
	// have one AK certificate (chain) signed by one Attestation CA at a time.

	return ak, nil
}

func attestationStatement(ctx context.Context, key *tpm.Key, akChain []*x509.Certificate) ([]byte, error) {
	params, err := key.CertificationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed obtaining key certification parameters: %w", err)
	}

	akChainBytes := make([][]byte, len(akChain))
	for i, cert := range akChain {
		akChainBytes[i] = cert.Raw
	}

	obj := &attestationObject{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      int64(-257), // AlgRS256 (COSE identifier); depends on type of the private key
			"x5c":      akChainBytes,
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		},
	}
	b, err := cbor.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func keyAuthDigest(jwk *jose.JSONWebKey, token string) ([]byte, error) {
	keyAuth, err := acme.KeyAuthorization(token, jwk)
	if err != nil {
		return nil, err
	}

	hashedKeyAuth := sha256.Sum256([]byte(keyAuth))
	return hashedKeyAuth[:], nil
}

func generateKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}
	hash := sha256.Sum256(b)
	return hash[:], nil
}

// hasValidIdentity indicates if the AK has an associated certificate
// that includes a valid identity. Currently we only consider certificates
// that encode the TPM EK public key ID as one of its URI SANs, which is
// the default behavior of the Smallstep Attestation CA.
func hasValidIdentity(ak *tpm.AK, keyID []byte) bool {
	chain := ak.CertificateChain()
	if len(chain) == 0 {
		return false
	}
	akCert := chain[0]

	// TODO(hs): before continuing, add check if the cert is still valid?

	// the Smallstep Attestation CA will issue AK certifiates that
	// contain the EK public key ID encoded as an URN by default.
	keyIDURL := &url.URL{
		Scheme: "urn",
		Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID),
	}

	for _, u := range akCert.URIs {
		if strings.EqualFold(keyIDURL.String(), u.String()) {
			return true
		}
	}

	// TODO(hs): scan through other SANs too, to find other valid identities.

	return false
}

type attestationClient struct {
	client  http.Client
	baseURL *url.URL
}

type attestationClientOptions struct {
	rootCAs  *x509.CertPool
	insecure bool
}

type attestationClientOption func(o *attestationClientOptions) error

func withRootsFile(filename string) attestationClientOption {
	return func(o *attestationClientOptions) error {
		if filename == "" {
			return nil
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed reading %q: %w", filename, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("failed parsing %q: no certificates found", filename)
		}
		o.rootCAs = pool
		return nil
	}
}

func withInsecure() attestationClientOption {
	return func(o *attestationClientOptions) error {
		o.insecure = true
		return nil
	}
}

// newAttestationClient creates a new attestationClient
func newAttestationClient(tpmAttestationCABaseURL string, options ...attestationClientOption) (*attestationClient, error) {
	u, err := url.Parse(tpmAttestationCABaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URL: %w", err)
	}

	opts := &attestationClientOptions{}
	for _, o := range options {
		if err := o(opts); err != nil {
			return nil, fmt.Errorf("failed applying option to attestation client: %w", err)
		}
	}

	client := http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs:            opts.rootCAs,
				InsecureSkipVerify: opts.insecure, //nolint:gosec // intentional insecure
			},
		},
	}

	return &attestationClient{
		client:  client,
		baseURL: u,
	}, nil
}

// performAttestation performs remote attestation using the AK backed by TPM t.
func (ac *attestationClient) performAttestation(ctx context.Context, t *tpm.TPM, ak *tpm.AK) ([]*x509.Certificate, error) {
	// TODO(hs): what about performing attestation for an existing AK identifier and/or cert, but
	// with a different Attestation CA? It seems sensible to enroll with that other Attestation CA,
	// but it needs capturing some knowledge about the Attestation CA with the AK (cert). Possible to
	// derive that from the intermediate and/or root CA and/or fingerprint, somehow? Or the attestation URI?

	eks, err := t.GetEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving EKs from TPM: %w", err)
	}

	attestParams, err := ak.AttestationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting AK attestation parameters: %w", err)
	}

	attResp, err := ac.attest(ctx, eks, attestParams)
	if err != nil {
		return nil, fmt.Errorf("failed attesting AK: %w", err)
	}

	encryptedCredentials := tpm.EncryptedCredential{
		Credential: attResp.Credential,
		Secret:     attResp.Secret,
	}

	// activate the credential with the TPM
	secret, err := ak.ActivateCredential(ctx, encryptedCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed activating credential: %w", err)
	}

	secretResp, err := ac.secret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("failed validating secret: %w", err)
	}

	akChain := make([]*x509.Certificate, len(secretResp.CertificateChain))
	for i, certBytes := range secretResp.CertificateChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing certificate: %w", err)
		}
		akChain[i] = cert
	}

	return akChain, nil
}

type attestationParameters struct {
	Public                  []byte `json:"public"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat"`
	CreateData              []byte `json:"createData"`
	CreateAttestation       []byte `json:"createAttestation"`
	CreateSignature         []byte `json:"createSignature"`
}

type attestationRequest struct {
	TPMVersion   attest.TPMVersion     `json:"version"`
	EKPub        []byte                `json:"ek"`
	EKCerts      [][]byte              `json:"ekCerts"`
	AKCert       []byte                `json:"akCert"`
	AttestParams attestationParameters `json:"params"`
}

type attestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"` // encrypted secret
}

// attest performs the HTTP POST request to the `/attest` endpoint of the
// Attestation CA.
func (ac *attestationClient) attest(ctx context.Context, eks []*tpm.EK, attestParams attest.AttestationParameters) (*attestationResponse, error) {
	var ekCerts [][]byte
	var ekPub []byte
	var err error

	// TPM can have multiple EKs; typically an RSA and/or ECDSA key will
	// be present. A certificate is optional.
	for _, ek := range eks {
		ekCert := ek.Certificate()
		if ekCert == nil {
			// TODO(hs): pick a specific EK public key if there are multiple?
			if ekPub, err = x509.MarshalPKIXPublicKey(ek.Public()); err != nil {
				return nil, fmt.Errorf("failed marshaling public key: %w", err)
			}
		} else {
			ekCerts = append(ekCerts, ekCert.Raw)
		}
	}

	ar := attestationRequest{
		TPMVersion: attest.TPMVersion20,
		EKCerts:    ekCerts,
		EKPub:      ekPub,
		AttestParams: attestationParameters{
			Public:                  attestParams.Public,
			UseTCSDActivationFormat: attestParams.UseTCSDActivationFormat,
			CreateData:              attestParams.CreateData,
			CreateAttestation:       attestParams.CreateAttestation,
			CreateSignature:         attestParams.CreateSignature,
		},
	}

	body, err := json.Marshal(ar)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling attestation request: %w", err)
	}

	attestURL := ac.baseURL.JoinPath("attest").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed creating POST http request for %q: %w", attestURL, err)
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed performing attestation request with Attestation CA %q: %w", attestURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %q failed with HTTP status %q", attestURL, resp.Status)
	}

	var attResp attestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return nil, fmt.Errorf("failed decoding attestation response: %w", err)
	}

	return &attResp, nil
}

type secretRequest struct {
	Secret []byte `json:"secret"` // decrypted secret
}

type secretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}

// secret performs the HTTP POST request to the `/secret` endpoint of the
// Attestation CA.
func (ac *attestationClient) secret(ctx context.Context, secret []byte) (*secretResponse, error) {
	sr := secretRequest{
		Secret: secret,
	}

	body, err := json.Marshal(sr)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling secret request: %w", err)
	}

	secretURL := ac.baseURL.JoinPath("secret").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secretURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed creating POST http request for %q: %w", secretURL, err)
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed performing secret request with attestation CA %q: %w", secretURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %q failed with HTTP status %q", secretURL, resp.Status)
	}

	var secretResp secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return nil, fmt.Errorf("failed decoding secret response: %w", err)
	}

	return &secretResp, nil
}
