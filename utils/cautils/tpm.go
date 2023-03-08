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
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certinfo"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"
)

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

type secretRequest struct {
	Secret []byte `json:"secret"` // decrypted secret
}

type secretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}

func doTPMAttestation(clictx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string, af *acmeFlow) error {
	// TODO: identifier for permanent-identifier handled differently? Can we provide just whatever we want and is that secure?
	// The permanent-identifier should probably be more like a hardware identifier specific to the device, not just any hostname or IP.
	// The hardware identifier (e.g. serial) should then be mapped to something else that is more useful for a server cert, like a
	// hostname. Or is it more like a device can request a hostname and the attestation can be used to verify that the device is
	// actually what it says it's saying and allowed to request that specific hostname?

	ctx := context.Background()

	tpmAttestationCABaseURL := clictx.String("attestation-ca-url")
	if tpmAttestationCABaseURL == "" {
		return fmt.Errorf("flag %q cannot be empty", "--attestation-ca-url")
	}

	ui.Printf("Using Device Attestation challenge to validate %q", identifier)
	ui.Printf(" .") // Indicates passage of time.

	tpmStorageDirectory := clictx.String("tpm-storage-directory")
	t, err := tpm.New(tpm.WithStore(tpmstorage.NewDirstore(tpmStorageDirectory)))
	if err != nil {
		return fmt.Errorf("failed initializing TPM: %w", err)
	}

	ctx = tpm.NewContext(ctx, t)

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

	var ak *tpm.AK
	if ak, err = t.GetAK(ctx, identifier); err != nil {
		// return early if an error occurred that doesn't indicate that the AK does not exist
		if !errors.Is(err, tpm.ErrNotFound) {
			return fmt.Errorf("failed getting AK: %w", err)
		}

		if ak, err = t.CreateAK(ctx, identifier); err != nil {
			return fmt.Errorf("failed creating AK: %w", err)
		}
	}

	akChain, err := akChain(ctx, t, ak, tpmAttestationCABaseURL)
	if err != nil {
		return fmt.Errorf("failed getting AK certificate for %q: %w", identifier, err)
	}

	if len(akChain) == 0 {
		return fmt.Errorf("no AK certificate (chain) available for %q", identifier)
	}

	// Generate the certificate key, include the ACME key authorization in the
	// the TPM certification data.
	data, err := keyAuthDigest(ac.Key, ch.Token)
	if err != nil {
		return fmt.Errorf("failed creating key authorization: %w", err)
	}

	config := tpm.AttestKeyConfig{
		Algorithm:      "RSA",
		Size:           2048,
		QualifyingData: data,
	}
	attestedKey, err := t.AttestKey(ctx, identifier, "", config)
	if err != nil {
		return fmt.Errorf("failed creating new key attested by AK %q", identifier)
	}

	signer, err := attestedKey.Signer(ctx)
	if err != nil {
		return fmt.Errorf("failed getting signer for key %q", attestedKey.Name())
	}

	// passing the TPM key to the ACME flow, so that it can be used as a signer
	// TODO(hs): this is a bit of a hack that needs refactoring; should ideally behave similar to `step` format
	af.tpmSigner = signer

	// Generate the WebAuthn attestation statement.
	attStmt, err := attestationStatement(ctx, attestedKey, akChain)
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

	return nil
}

func attestationStatement(ctx context.Context, key *tpm.Key, akChain []*x509.Certificate) ([]byte, error) {

	params, err := key.CertificationParameters(ctx)
	if err != nil {
		return nil, err
	}

	akChainBytes := make([][]byte, len(akChain))
	for i, cert := range akChain {
		akChainBytes[i] = cert.Raw
	}

	obj := &attestationObject{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      int64(-257), // AlgRS256
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

func akChain(ctx context.Context, t *tpm.TPM, ak *tpm.AK, tpmAttestationCABaseURL string) ([]*x509.Certificate, error) {

	// params, err := ak.AttestationParameters(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	// akPub, err := attest.ParseAKPublic(attest.TPMVersion20, params.Public)
	// if err != nil {
	// 	return nil, err
	// }

	// // TODO(hs): lookup AK certificate by akPub; perform attestation for `identifier` if not found
	// _ = akPub

	// TODO(hs): check if AK has associated AK certificate (chain). It it does, return that.
	// If not, continue with the attestation flow.
	// TODO(hs): perform precheck to verify the retrieved AK certificate chain
	// does belong to this TPM? Depending on how the certificate was obtained and stored,
	// it might've been altered somehow.
	// TODO(hs): what about performing attestation for an existing AK identifier and/or cert, but
	// with a different Attestation CA? It seems sensible to enroll with that other Attestation CA,
	// but it needs capturing some knowledge about the Attestation CA with the AK (cert). Possible to
	// derive that from the intermediate and/or root CA and/or fingerprint, somehow? Or the attestation URI?

	eks, err := t.GetEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving EKs from TPM: %w", err)
	}
	var ekCerts [][]byte
	var ekPub []byte

	for _, ek := range eks {
		ekCert := ek.Certificate()
		if ekCert == nil {
			if ekPub, err = x509.MarshalPKIXPublicKey(ek.Public); err != nil {
				return nil, fmt.Errorf("failed marshaling public key: %w", err)
			}
		} else {
			ekCerts = append(ekCerts, ekCert.Raw)
		}
	}

	attestParams, err := ak.AttestationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting AK attestation parameters: %w", err)
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

	// TODO(hs): support a new attestation request with existing AK cert?
	// if akCert != nil {
	// 	ar.AKCert = akCert.Raw
	// }

	body, err := json.Marshal(ar)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling attestation request: %w", err)
	}

	attestURL := tpmAttestationCABaseURL + "/attest"
	req, err := http.NewRequest(http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed creating POST http request for %q: %w", attestURL, err)
	}

	// TODO(hs): implement a client, similar to the caClient and acmeClient, that uses sane defaults and
	// automatically uses the Attestation CA root as trust anchor.
	client := http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // quick hack; don't verify TLS for now
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed performing attestation request with attestation CA %q: %w", attestURL, err)
	}

	var attResp attestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return nil, fmt.Errorf("failed decoding attestation response: %w", err)
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

	sr := secretRequest{
		Secret: secret,
	}

	body, err = json.Marshal(sr)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling secret request: %w", err)
	}

	secretURL := tpmAttestationCABaseURL + "/secret"
	req, err = http.NewRequest(http.MethodPost, secretURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed creating POST http request for %q: %w", secretURL, err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed performing secret request with attestation CA %q: %w", secretURL, err)
	}

	var secretResp secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return nil, fmt.Errorf("failed decoding secret response: %w", err)
	}

	akChain := make([]*x509.Certificate, len(secretResp.CertificateChain))
	for i, certBytes := range secretResp.CertificateChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing certificate: %w", err)
		}

		// TODO(hs): don't output this by default (similar to TPM info)
		info, err := certinfo.CertificateText(cert)
		if err != nil {
			return nil, fmt.Errorf("failed getting certificate text: %w", err)
		}
		ui.Printf(fmt.Sprintf("\n\n%s\n\n", info))

		akChain[i] = cert
	}

	// TODO(hs): persist the AK chain to the TPM storage, so that when a new key
	// needs to be created with an attestation, the existing AK chain can be used
	// in the attestation flow.

	return akChain, nil
}

// Borrowed from:
// https://github.com/golang/crypto/blob/master/acme/acme.go#L748
func keyAuthDigest(jwk *jose.JSONWebKey, token string) ([]byte, error) {
	th, err := jwk.Thumbprint(crypto.SHA256)
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", token, th)))
	return digest[:], err
}
