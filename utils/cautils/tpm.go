package cautils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
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
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/smallstep/go-attestation/attest"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"

	"github.com/smallstep/cli/utils"
)

func doTPMAttestation(clictx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string, af *acmeFlow) error {
	attestationURI := clictx.String("attestation-uri")
	tpmStorageDirectory := clictx.String("tpm-storage-directory")
	tpmAttestationCABaseURL := clictx.String("attestation-ca-url")
	tpmAttestationCARootFile := clictx.String("attestation-ca-root")
	tpmAttestationCAInsecure := clictx.Bool("attestation-ca-insecure")
	insecure := clictx.Bool("insecure")

	keyName, attURI, err := parseTPMAttestationURI(attestationURI)
	if err != nil {
		return fmt.Errorf("failed parsing --attestation-uri: %w", err)
	}

	if tpmAttestationCABaseURL == "" {
		tpmAttestationCABaseURL = attURI.Get("attestation-ca-url")
		if tpmAttestationCABaseURL == "" {
			return errs.RequiredFlag(clictx, "attestation-ca-url")
		}
	}

	tpmOpts := []tpm.NewTPMOption{
		tpm.WithStore(tpmstorage.NewDirstore(tpmStorageDirectory)),
	}
	if device := attURI.Get("device"); device != "" {
		tpmOpts = append(tpmOpts, tpm.WithDeviceName(device))
	}

	t, err := tpm.New(tpmOpts...)
	if err != nil {
		return fmt.Errorf("failed initializing TPM: %w", err)
	}

	kty, crv, size, err := utils.GetKeyDetailsFromCLI(clictx, insecure, "kty", "curve", "size")
	if err != nil {
		return fmt.Errorf("failed getting key details: %w", err)
	}

	var inputSize int
	inputKeyType := kty
	switch kty {
	case "EC":
		switch crv {
		case "P-256":
			inputSize = 256
		case "P-384":
			inputSize = 384
		case "P-521":
			inputSize = 521
		default:
			return fmt.Errorf("unsupported curve: %q", crv)
		}
		inputKeyType = "ECDSA"
	case "RSA":
		inputSize = size
	default:
		return fmt.Errorf("unsupported key type: %q", kty)
	}

	ctx := tpm.NewContext(context.Background(), t)
	info, err := t.Info(ctx)
	if err != nil {
		return fmt.Errorf("failed retrieving TPM info: %w", err)
	}

	ui.Printf("TPM INFO:")
	ui.Printf("\nVersion: %s", info.Version)
	ui.Printf("\nInterface: %s", info.Interface)
	ui.Printf("\nManufacturer: %s", info.Manufacturer)
	ui.Printf("\nVendor info: %s", info.VendorInfo)
	ui.Printf("\nFirmware version: %s\n", info.FirmwareVersion)

	ui.Printf("Using Device Attestation challenge to validate %q", identifier)
	ui.Printf(" .") // Indicates passage of time.

	// prepare a client to perform attestation with an Attestation CA
	attestationClientOptions := []attestationClientOption{withRootsFile(tpmAttestationCARootFile)}
	if tpmAttestationCAInsecure {
		attestationClientOptions = append(attestationClientOptions, withInsecure())
	}
	atc, err := newAttestationClient(tpmAttestationCABaseURL, attestationClientOptions...)
	if err != nil {
		return fmt.Errorf("failed creating attestation client: %w", err)
	}

	// get or create an AK, including an AK certificate chain
	ak, err := getAK(ctx, t, atc)
	if err != nil {
		return fmt.Errorf("failed getting AK: %w", err)
	}

	// generate the key authorization digest
	data, err := keyAuthDigest(ac.Key, ch.Token)
	if err != nil {
		return fmt.Errorf("failed creating key authorization: %w", err)
	}

	// create a new key, attested by the AK. Note that the
	// key authorization digest is used as the qualifying data,
	// effectively resulting in binding the attestation of a key
	// to the specific challenge (token) and ACME account key. Because
	// the token will be different for a new ACME order, a single TPM
	// backed key can't be (re)used for multiple orders. So, when a new
	// certificate is required, a new key has to be attested. The CLI
	// does not automatically delete the previous key of the same name,
	// as it may still be required. It is thus up to the user to use
	// either a different key name or to delete the key first.
	config := tpm.AttestKeyConfig{
		Algorithm:      inputKeyType,
		Size:           inputSize,
		QualifyingData: data,
	}
	attestedKey, err := t.AttestKey(ctx, ak.Name(), keyName, config)
	if err != nil {
		return fmt.Errorf("failed creating new key attested by AK %q: %w", ak.Name(), err)
	}

	// generate the WebAuthn attestation statement.
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
func parseTPMAttestationURI(attestationURI string) (string, *uri.URI, error) {
	if attestationURI == "" {
		return "", nil, errors.New("attestation URI cannot be empty")
	}
	if !strings.HasPrefix(attestationURI, "tpmkms:") {
		return "", nil, fmt.Errorf("%q does not start with tpmkms", attestationURI)
	}
	u, err := uri.Parse(attestationURI)
	if err != nil {
		return "", nil, fmt.Errorf("failed parsing %q: %w", attestationURI, err)
	}
	var name string
	if name = u.Get("name"); name == "" {
		return "", nil, fmt.Errorf("failed parsing %q: name is missing", attestationURI)
	}
	// TODO(hs): more properties for objects created/attested in TPM
	return name, u, nil
}

// getAK returns an AK suitable for attesting the identifier that is requested. The
// current behavior is to look for an AK backed by the TPM that has been issued a
// certificate that includes the EK public key ID as one of it URI SANs. The AK itself
// is identified by the hexadecimal representation of the EK public key. If no AK
// is found, a new one is created. If the AK has not valid certificate, the system
// enrolls with an Attestation CA using the `attesationClient`.
func getAK(ctx context.Context, t *tpm.TPM, ac *attestationClient) (*tpm.AK, error) {
	eks, err := t.GetEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving TPM EKs: %w", err)
	}

	ek := getPreferredEK(eks)
	if ek == nil {
		return nil, errors.New("no TPM EKs available")
	}
	ekPublic := ek.Public()
	ekKeyID, err := generateKeyID(ekPublic)
	if err != nil {
		return nil, fmt.Errorf("failed getting EK public key ID: %w", err)
	}
	ekKeyURL := ekURL(ekKeyID)

	ekHexFingerprint, err := keyutil.EncodedFingerprint(ekPublic, keyutil.HexFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed creating EK fingerprint: %w", err)
	}

	// strip off "<hash>:"
	ekHexFingerprint = strings.Split(ekHexFingerprint, ":")[1]

	// look for an AK named after the EK hex fingerprint by default
	var ak *tpm.AK
	if ak, err = t.GetAK(ctx, ekHexFingerprint); err != nil {
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
	if len(akChain) == 0 || !hasValidIdentity(ak, ekKeyURL) {
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
	if !hasValidIdentity(ak, ekKeyURL) {
		return nil, fmt.Errorf("AK certificate (chain) not valid for EK %q", ekKeyURL)
	}

	// TODO(hs): perform precheck to verify the retrieved AK certificate chain
	// does belong to the TPM that's in use? Depending on how the certificate
	// was obtained and stored, it might've been altered somehow.
	// TODO(hs): support attestation flow with multiple Attestation CAs for a
	// single AK? Currently an AK is identified just by its name and can only
	// have one AK certificate (chain) signed by one Attestation CA at a time.

	return ak, nil
}

// attestationStatement constructs and marshals the attestation
// object for the `tpm` format.
func attestationStatement(ctx context.Context, key *tpm.Key, akChain []*x509.Certificate) ([]byte, error) {
	params, err := key.CertificationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed obtaining key certification parameters: %w", err)
	}

	akChainBytes := make([][]byte, len(akChain))
	for i, cert := range akChain {
		akChainBytes[i] = cert.Raw
	}

	pub, err := tpm2.DecodePublic(params.Public)
	if err != nil {
		return nil, fmt.Errorf("failed decoding TPM public key: %w", err)
	}

	var alg int64
	switch pub.Type {
	case tpm2.AlgRSA:
		alg = -257 // RS256 COSE Algorithm Identifier
	case tpm2.AlgECC:
		alg = -7 // ES256 COSE Algorithm Identifier
	default:
		return nil, fmt.Errorf("unsupported TPM public key type: 0x%x", pub.Type)
	}

	obj := &attestationObject{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      alg,
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

// keyAuthDigest generates the ACME key authorization digest.
func keyAuthDigest(jwk *jose.JSONWebKey, token string) ([]byte, error) {
	keyAuth, err := acme.KeyAuthorization(token, jwk)
	if err != nil {
		return nil, err
	}

	hashedKeyAuth := sha256.Sum256([]byte(keyAuth))
	return hashedKeyAuth[:], nil
}

// generateKeyID generates a key identifier from the
// SHA256 hash of the public key.
func generateKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}
	hash := sha256.Sum256(b)
	return hash[:], nil
}

// ekURL generates an EK URI containing the encoded key identifier
// for the EK.
func ekURL(keyID []byte) *url.URL {
	return &url.URL{
		Scheme: "urn",
		Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID),
	}
}

// hasValidIdentity indicates if the AK has an associated certificate
// that includes a valid identity. Currently we only consider certificates
// that encode the TPM EK public key ID as one of its URI SANs, which is
// the default behavior of the Smallstep Attestation CA.
func hasValidIdentity(ak *tpm.AK, ekURL *url.URL) bool {
	chain := ak.CertificateChain()
	if len(chain) == 0 {
		return false
	}
	akCert := chain[0]

	// TODO(hs): before continuing, add check if the cert is still valid?

	// the Smallstep Attestation CA will issue AK certifiates that
	// contain the EK public key ID encoded as an URN by default.
	for _, u := range akCert.URIs {
		if strings.EqualFold(ekURL.String(), u.String()) {
			return true
		}
	}

	// TODO(hs): we could consider checking other values to contain
	// a usable identity too.

	return false
}

// getPreferredEK returns the first RSA TPM EK found. If no RSA
// EK exists, it returns the first ECDSA EK found.
func getPreferredEK(eks []*tpm.EK) (ek *tpm.EK) {
	var fallback *tpm.EK
	for _, ek = range eks {
		if _, isRSA := ek.Public().(*rsa.PublicKey); isRSA {
			return
		}
		if fallback == nil {
			fallback = ek
		}
	}
	return fallback
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

// withRootsFile can be used to set the trusted roots when
// setting up a TLS connection.
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

// withInsecure disables TLS server certificate chain checking.
// In general this shouldn't be used, but it can be of use in
// during development and testing.
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
				InsecureSkipVerify: opts.insecure, //nolint:gosec // intentional insecure if provided as option
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

	info, err := t.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving info from TPM: %w", err)
	}

	eks, err := t.GetEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving EKs from TPM: %w", err)
	}

	attestParams, err := ak.AttestationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting AK attestation parameters: %w", err)
	}

	attResp, err := ac.attest(ctx, info, eks, attestParams)
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

type tpmInfo struct {
	Version         attest.TPMVersion `json:"version,omitempty"`
	Manufacturer    string            `json:"manufacturer,omitempty"`
	Model           string            `json:"model,omitempty"`
	FirmwareVersion string            `json:"firmwareVersion,omitempty"`
}

type attestationParameters struct {
	Public                  []byte `json:"public,omitempty"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat,omitempty"`
	CreateData              []byte `json:"createData,omitempty"`
	CreateAttestation       []byte `json:"createAttestation,omitempty"`
	CreateSignature         []byte `json:"createSignature,omitempty"`
}

type attestationRequest struct {
	TPMInfo      tpmInfo               `json:"tpmInfo"`
	EKPub        []byte                `json:"ek,omitempty"`
	EKCerts      [][]byte              `json:"ekCerts,omitempty"`
	AKCert       []byte                `json:"akCert,omitempty"`
	AttestParams attestationParameters `json:"params"`
}

type attestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"` // encrypted secret
}

// attest performs the HTTP POST request to the `/attest` endpoint of the
// Attestation CA.
func (ac *attestationClient) attest(ctx context.Context, info *tpm.Info, eks []*tpm.EK, attestParams attest.AttestationParameters) (*attestationResponse, error) {
	var ekCerts [][]byte
	var ekPub []byte
	var err error

	// TPM can have multiple EKs; typically an RSA and/or ECDSA key will
	// be present. A certificate is optional. We prefer using certificates
	// over just the EK public key.
	for _, ek := range eks {
		if ekCert := ek.Certificate(); ekCert != nil {
			ekCerts = append(ekCerts, ekCert.Raw)
		}
	}

	ek := getPreferredEK(eks)
	if ek == nil {
		return nil, errors.New("no EK available")
	}
	if ekPub, err = x509.MarshalPKIXPublicKey(ek.Public()); err != nil {
		return nil, fmt.Errorf("failed marshaling public key: %w", err)
	}

	ar := attestationRequest{
		TPMInfo: tpmInfo{
			Version:         attest.TPMVersion20,
			Manufacturer:    strconv.FormatUint(uint64(info.Manufacturer.ID), 10),
			Model:           info.VendorInfo,
			FirmwareVersion: info.FirmwareVersion.String(),
		},
		EKCerts: ekCerts,
		EKPub:   ekPub,
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
