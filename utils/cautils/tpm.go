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
	"log"
	"math/big"
	"net/http"
	neturl "net/url"
	"path"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certinfo"

	smalltpm "github.com/smallstep/step-tpm-plugin/pkg/tpm"
	smalltpmstorage "github.com/smallstep/step-tpm-plugin/pkg/tpm/storage"

	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
)

// TODO(hs): all required?
type AttestationParameters struct {
	Public                  []byte `json:"public"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat"`
	CreateData              []byte `json:"createData"`
	CreateAttestation       []byte `json:"createAttestation"`
	CreateSignature         []byte `json:"createSignature"`
}

type AttestationRequest struct {
	TPMVersion   attest.TPMVersion     `json:"version"`
	EKPub        []byte                `json:"ek"`
	EKCerts      [][]byte              `json:"ekCerts"`
	AKCert       []byte                `json:"akCert"`
	AttestParams AttestationParameters `json:"params"`
}

type AttestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"` // encrypted secret
}

type SecretRequest struct {
	Secret []byte `json:"secret"` // decrypted secret
}

type SecretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}

type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

type tpmKey interface {
}

func doTPMAttestation(ctx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string, af *acmeFlow) error {
	// TODO: identifier for permanent-identifier handled differently? Can we provide just whatever we want and is that secure?
	// The permanent-identifier should probably be more like a hardware identifier specific to the device, not just any hostname or IP.
	// The hardware identifier (e.g. serial) should then be mapped to something else that is more useful for a server cert, like a
	// hostname. Or is it more like a device can request a hostname and the attestation can be used to verify that the device is
	// actually what it says it's saying and allowed to request that specific hostname?

	// 1. Prepare the mode to be ran
	// 2. Validate the challenge
	// 3. Get the challenge?
	// 4. Perform cleanup

	ui.Printf("Using Standalone Mode Device Attestation challenge to validate `%s`", identifier)

	// ch is the chal := authz.Challenges[0]
	// Generate the certificate key, include the ACME key authorization in the
	// the TPM certification data.
	tpm, ak, akCert, err := tpmInit(identifier)
	if err != nil {
		log.Fatal(err)
	}

	info, err := tpm.Info(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// TODO(hs): remove this output
	ui.Printf("\nTPM INFO:")
	ui.Printf("\nversion: %d", info.Version)
	ui.Printf("\ninterface: %d", info.Interface)
	ui.Printf("\nmanufacturer: %s", info.Manufacturer)
	ui.Printf("\nvendor info: %s", info.VendorInfo)
	ui.Printf("\nfirmware version: %d.%d\n", info.FirmwareVersionMajor, info.FirmwareVersionMinor)

	eks, err := tpm.GetEKs(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	var ekCerts [][]byte
	var ekPub []byte

	for _, ek := range eks {
		ekCert := ek.Certificate
		if url := ek.CertificateURL; ekCert == nil && url != "" {
			var u *neturl.URL
			u, err = neturl.Parse(url)
			if err != nil {
				log.Fatal(err)
			}

			// Ensure the URL is in the right format; for Intel TPMs, the path
			// parameter contains the base64 encoding of the hash of the public key,
			// potentially containing padding characters, which will results in a 403,
			// if not transformed to `%3D`. The below has currently only be tested for
			// Intel TPMs, which connect to https://ekop.intel.com/ekcertservice. It may
			// be different for other URLs. Ideally, I think this should be fixed in
			// the underlying TPM library to contain the right URL? The `intelEKURL` already
			// seems to do URLEncoding, though. Why do we still get an `=` then?
			s := u.String()
			h := path.Base(s)
			h = strings.ReplaceAll(h, "=", "%3D") // TODO(hs): no better function in Go to do this in paths? https://github.com/golang/go/issues/27559;
			s = s[:strings.LastIndex(s, "/")+1] + h

			u, err = neturl.Parse(s)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("ek url:", u)
			var r *http.Response
			r, err = http.Get(u.String())
			if err != nil {
				log.Fatal(err)
			}
			defer r.Body.Close()

			if r.StatusCode != http.StatusOK {
				log.Fatalf("http get resulted in %d", r.StatusCode)
			}

			var c intelEKCertResponse
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				log.Fatal(err)
			}

			cb, err := base64.URLEncoding.DecodeString(c.Certificate)
			if err != nil {
				log.Fatal(err)
			}

			ekCert, err = attest.ParseEKCertificate(cb)
			if err != nil {
				log.Fatal(err)
			}
		}

		if ekCert == nil {
			log.Println("no EK certificate found")
			if ekPub, err = x509.MarshalPKIXPublicKey(ek.Public); err != nil {
				log.Fatal(err)
			}
		} else {
			ekCerts = append(ekCerts, ekCert.Raw)
		}
	}

	// TODO: refactor this into using the smalltpm package
	atpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatal(err)
	}
	defer atpm.Close()

	aak, err := atpm.LoadAK(ak.Data)
	if err != nil {
		log.Fatal(err)
	}
	defer aak.Close(atpm)

	attestParams := aak.AttestationParameters()

	// TODO: should the request include nonce? Or token? Or the KeyAuthDigest? Combination/All?
	// TODO: should this include a CSR?
	ar := AttestationRequest{
		TPMVersion: attest.TPMVersion(info.Version),
		EKCerts:    ekCerts,
		EKPub:      ekPub,
		AttestParams: AttestationParameters{
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
		log.Fatal(err)
	}

	tpmAttestationCABaseURL := ctx.String("attestation-ca-url")
	if tpmAttestationCABaseURL == "" { // TODO(hs): move this check earlier in the process?
		log.Fatal(errors.New("--attestation-ca-url must be provided"))
	}

	attestURL := tpmAttestationCABaseURL + "/attest"
	req, err := http.NewRequest(http.MethodPost, attestURL, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	var attResp AttestationResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		log.Fatal(err)
	}

	encryptedCredentials := attest.EncryptedCredential{
		Credential: attResp.Credential,
		Secret:     attResp.Secret,
	}

	// TODO: load the AK, if it was persisted outside of the TPM. In the POC we have it in memory, so no need to do that.

	// activate the credential // TODO: refactor this into using the library function
	secret, err := aak.ActivateCredential(atpm, encryptedCredentials)
	if err != nil {
		log.Fatal(err)
	}

	sr := SecretRequest{
		Secret: secret,
	}

	body, err = json.Marshal(sr)
	if err != nil {
		log.Fatal(err)
	}

	secretURL := tpmAttestationCABaseURL + "/secret"
	req, err = http.NewRequest(http.MethodPost, secretURL, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}

	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	var secretResp SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		log.Fatal(err)
	}

	akChain := [][]byte{}
	for _, certBytes := range secretResp.CertificateChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Fatal(err)
		}
		info, err := certinfo.CertificateText(cert)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(info)
		akChain = append(akChain, certBytes)
	}

	data, err := keyAuthDigest(ac.Key, ch.Token)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	certKey, err := tpm.GetSigner(context.Background(), attestedKey.Name)
	if err != nil {
		log.Fatal(err)
	}

	// passing the TPM key to the ACME flow, so that it can be used as a signer
	// TODO(hs): this is a bit of a hack that needs refactoring
	af.tpmSigner = certKey

	// Generate the WebAuthn attestation statement.
	attStmt, err := attestationStatement(tpm, attestedKey, akChain...)
	if err != nil {
		log.Fatal(err)
	}

	challengeBody := struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attStmt),
	}

	payload, err := json.Marshal(challengeBody)
	if err != nil {
		return errors.Wrapf(err, "error marshaling challenge body")
	}

	if err := ac.ValidateWithPayload(ch.URL, payload); err != nil {
		ui.Printf(" Error!\n\n")
		//mode.Cleanup()
		return errors.Wrapf(err, "error validating ACME Challenge at %s", ch.URL)
	}
	var (
		isValid = false
		vch     *acme.Challenge
		//err     error
	)
	time.Sleep(time.Second) // brief sleep to allow server time to validate challenge.
	for attempts := 0; attempts < 10; attempts++ {
		vch, err = ac.GetChallenge(ch.URL)
		if err != nil {
			ui.Printf(" Error!\n\n")
			//mode.Cleanup()
			return errors.Wrapf(err, "error retrieving ACME Challenge at %s", ch.URL)
		}
		if vch.Status == "valid" {
			isValid = true
			break
		}
		ui.Printf(".")
		time.Sleep(5 * time.Second)
	}
	if !isValid {
		ui.Printf(" Error!\n\n")
		//mode.Cleanup()
		return errors.Errorf("Unable to validate challenge: %+v", vch)
	}
	// if err := mode.Cleanup(); err != nil {
	//  return err
	// }
	ui.Printf(" done!\n")

	return nil
}

type AttestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

func attestationStatement(t *smalltpm.TPM, key smalltpm.Key, akChain ...[]byte) ([]byte, error) {

	// TODO: refactor so that key has the parameters itself?
	params, err := t.GetKeyCertificationParameters(context.Background(), key.Name)
	if err != nil {
		return nil, err
	}

	obj := &AttestationObject{
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

	ak, err := t.CreateAK(context.Background(), identifier)
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

	// TODO: refactor this into using the smalltpm package
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	aak, err := tpm.LoadAK(ak.Data)
	if err != nil {
		return nil, err
	}
	defer aak.Close(tpm)

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
	akPub, err := attest.ParseAKPublic(attest.TPMVersion20, aak.AttestationParameters().Public)
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
