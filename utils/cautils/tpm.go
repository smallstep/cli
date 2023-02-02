package cautils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certinfo"

	smalltpm "github.com/smallstep/step-tpm-plugin/pkg/tpm"
	smalltpmstorage "github.com/smallstep/step-tpm-plugin/pkg/tpm/storage"

	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
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

func doTPMAttestation(ctx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string, af *acmeFlow) error {
	// TODO: identifier for permanent-identifier handled differently? Can we provide just whatever we want and is that secure?
	// The permanent-identifier should probably be more like a hardware identifier specific to the device, not just any hostname or IP.
	// The hardware identifier (e.g. serial) should then be mapped to something else that is more useful for a server cert, like a
	// hostname. Or is it more like a device can request a hostname and the attestation can be used to verify that the device is
	// actually what it says it's saying and allowed to request that specific hostname?

	tpmAttestationCABaseURL := ctx.String("attestation-ca-url")
	if tpmAttestationCABaseURL == "" {
		return fmt.Errorf("flag %q cannot be empty", "--attestation-ca-url")
	}

	ui.Printf("Using Device Attestation challenge to validate %q", identifier)
	ui.Printf(" .") // Indicates passage of time.

	// ch is the chal := authz.Challenges[0]
	// Generate the certificate key, include the ACME key authorization in the
	// the TPM certification data.
	tpm, ak, akCert, err := tpmInit(identifier)
	if err != nil {
		return fmt.Errorf("error initializing TPM: %w", err)
	}

	info, err := tpm.Info(context.Background())
	if err != nil {
		return fmt.Errorf("error retrieving TPM info: %w", err)
	}

	// TODO(hs): remove this from the standard output, unless debugging?
	ui.Printf("\nTPM INFO:")
	ui.Printf("\nversion: %d", info.Version)
	ui.Printf("\ninterface: %d", info.Interface)
	ui.Printf("\nmanufacturer: %d", info.Manufacturer)
	ui.Printf("\nvendor info: %s", info.VendorInfo)
	ui.Printf("\nfirmware version: %d.%d\n", info.FirmwareVersionMajor, info.FirmwareVersionMinor)

	eks, err := tpm.GetEKs(context.Background())
	if err != nil {
		return fmt.Errorf("error retrieving EKs from TPM: %w", err)
	}
	var ekCerts [][]byte
	var ekPub []byte

	for _, ek := range eks {
		ekCert := ek.Certificate
		if ekCert == nil {
			if ekPub, err = x509.MarshalPKIXPublicKey(ek.Public); err != nil {
				return fmt.Errorf("error marshaling public key: %w", err)
			}
		} else {
			ekCerts = append(ekCerts, ekCert.Raw)
		}
	}

	attestParams, err := ak.AttestationParameters(context.Background())
	if err != nil {
		return fmt.Errorf("error getting AK attestation parameters: %w", err)
	}

	// TODO: should the request include nonce? Or token? Or the KeyAuthDigest? Combination/All?
	// TODO: should this include a CSR?
	ar := attestationRequest{
		TPMVersion: attest.TPMVersion(info.Version),
		EKCerts:    ekCerts,
		EKPub:      ekPub,
		AttestParams: attestationParameters{
			Public:                  attestParams.Public,
			UseTCSDActivationFormat: attestParams.UseTCSDActivationFormat,
			CreateData:              attestParams.CreateData,
			CreateAttestation:       attestParams.CreateAttestation,
			CreateSignature:         attestParams.CreateSignature,
		},
		AKCert: akCert,
	}

	body, err := json.Marshal(ar)
	if err != nil {
		return fmt.Errorf("error marshaling attestation request: %w", err)
	}

	attestURL := tpmAttestationCABaseURL + "/attest"
	req, err := http.NewRequest(http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error creating POST http request for %q: %w", attestURL, err)
	}

	// TODO(hs): implement a client, similar to the caClient and acmeClient, that use sane defaults and
	// automatically use the CA root as trust anchor.
	client := http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // quick hack; don't verify TLS for now
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error performing attestation request with attestation CA %q: %w", attestURL, err)
	}

	var attResp attestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return fmt.Errorf("error decoding attestation response: %w", err)
	}

	encryptedCredentials := smalltpm.EncryptedCredential{
		Credential: attResp.Credential,
		Secret:     attResp.Secret,
	}

	// activate the credential
	secret, err := ak.ActivateCredential(context.Background(), encryptedCredentials)
	if err != nil {
		return fmt.Errorf("error activating credential: %w", err)
	}

	sr := secretRequest{
		Secret: secret,
	}

	body, err = json.Marshal(sr)
	if err != nil {
		return fmt.Errorf("error marshaling secret request: %w", err)
	}

	secretURL := tpmAttestationCABaseURL + "/secret"
	req, err = http.NewRequest(http.MethodPost, secretURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error creating POST http request for %q: %w", secretURL, err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("error performing secret request with attestation CA %q: %w", secretURL, err)
	}

	var secretResp secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return fmt.Errorf("error decoding secret response: %w", err)
	}

	akChain := [][]byte{}
	for _, certBytes := range secretResp.CertificateChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("error parsing certificate: %w", err)
		}

		// TODO(hs): don't output this by default (similar to TPM info)
		info, err := certinfo.CertificateText(cert)
		if err != nil {
			return fmt.Errorf("error getting certificate text: %w", err)
		}
		fmt.Println(info)

		akChain = append(akChain, certBytes)
	}

	data, err := keyAuthDigest(ac.Key, ch.Token)
	if err != nil {
		return fmt.Errorf("error creating key authorization: %w", err)
	}

	config := smalltpm.AttestKeyConfig{
		//Algorithm: attest.ECDSA,
		//Size:      256,
		// TODO(hs): I had to change this to RSA to make the AK key and the cert key type check out with each other. Check if this is indeed required.
		// TODO(hs): with attest.RSA, I get an error when decoding the public key on server side:  panic: parsing public key: missing rsa signature scheme. Not sure where that has to be added ATM.
		Algorithm:      "RSA",
		Size:           2048, // TODO(hs): 4096 didn't work on my RPi TPM. Look into why that's the case. Returned a TPM error; RCValue = 0x04;  value is out of range or is not correct for the context
		QualifyingData: data,
	}
	attestedKey, err := tpm.AttestKey(context.Background(), identifier, "", config)
	if err != nil {
		return fmt.Errorf("error creating new key attested by AK %q", identifier)
	}

	signer, err := attestedKey.Signer(context.Background())
	if err != nil {
		return fmt.Errorf("error getting signer for key %q", attestedKey.Name)
	}

	// passing the TPM key to the ACME flow, so that it can be used as a signer
	// TODO(hs): this is a bit of a hack that needs refactoring; should ideally behave similar to `step` format
	af.tpmSigner = signer

	// Generate the WebAuthn attestation statement.
	attStmt, err := attestationStatement(tpm, attestedKey, akChain...)
	if err != nil {
		return fmt.Errorf("error creating attestation statement: %w", err)
	}

	challengeBody := struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attStmt),
	}

	payload, err := json.Marshal(challengeBody)
	if err != nil {
		return fmt.Errorf("error marshaling challenge body: %w", err)
	}

	if err := ac.ValidateWithPayload(ch.URL, payload); err != nil {
		ui.Printf(" Error!\n\n")
		return fmt.Errorf("error validating ACME Challenge at %q: %w", ch.URL, err)
	}

	durationBetweenAttempts := 2 * time.Second
	if err := getChallengeStatus(ac, ch, durationBetweenAttempts); err != nil {
		ui.Printf(" Error!\n\n")
		return err
	}

	ui.Printf(" done!\n")

	return nil
}

func attestationStatement(t *smalltpm.TPM, key smalltpm.Key, akChain ...[]byte) ([]byte, error) {

	// TODO: refactor so that key has the parameters itself?
	params, err := key.CertificationParameters(context.Background())
	if err != nil {
		return nil, err
	}

	obj := &attestationObject{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      int64(-257), // AlgRS256
			"x5c":      akChain,
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

func tpmInit(identifier string) (*smalltpm.TPM, *smalltpm.AK, []byte, error) {

	t, err := smalltpm.New(smalltpm.WithStore(smalltpmstorage.NewDirstore("."))) // TODO: put in right location
	if err != nil {
		return nil, nil, nil, err
	}

	ak, err := t.CreateAK(context.Background(), identifier) // TODO(hs): AK might already exist
	if err != nil {
		return nil, nil, nil, err
	}

	akCert, err := akCert(t, ak, identifier)
	if err != nil {
		return nil, nil, nil, err
	}

	return t, &ak, akCert, nil
}

func akCert(t *smalltpm.TPM, ak smalltpm.AK, identifier string) ([]byte, error) {

	params, err := ak.AttestationParameters(context.Background())
	if err != nil {
		return nil, err
	}

	// TODO(hs): took this from example; shouldn't this be generated inside the TPM? Or is
	// it only used to be able to convey the AK public key in a cert, and does the signature
	// not matter?
	akRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// akRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	//  return nil, err
	// }
	akRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	permID := x509ext.PermanentIdentifier{
		IdentifierValue: identifier,
		// Assigner:        asn1.ObjectIdentifier{0, 1, 2, 3, 4},
	}
	san := &x509ext.SubjectAltName{
		PermanentIdentifiers: []x509ext.PermanentIdentifier{
			permID,
		},
	}
	ext, err := x509ext.MarshalSubjectAltName(san)
	if err != nil {
		return nil, err
	}
	akTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		ExtraExtensions: []pkix.Extension{ext},
	}
	akPub, err := attest.ParseAKPublic(attest.TPMVersion20, params.Public)
	if err != nil {
		return nil, err
	}

	// TODO(hs): use x509util.CreateCertificate?
	akCert, err := x509.CreateCertificate(rand.Reader, akTemplate, akRootTemplate, akPub.Public, akRootKey)
	if err != nil {
		return nil, err
	}

	return akCert, nil
}

// Borrowed from:
// https://github.com/golang/crypto/blob/master/acme/acme.go#L748
func keyAuthDigest(jwk *jose.JSONWebKey, token string) ([]byte, error) {
	th, err := jwk.Thumbprint(crypto.SHA256) // TODO(hs): verify this is the correct thumbprint
	// jwk, err := jwkEncode(pub)
	// if err != nil {
	//  return "", err
	// }
	// b := sha256.Sum256([]byte(jwk))
	// return base64.RawURLEncoding.EncodeToString(b[:]), nil
	// th, err := stdacme.JWKThumbprint(pub)
	// if err != nil {
	//  return nil, err
	// }
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", token, th)))
	return digest[:], err
}
