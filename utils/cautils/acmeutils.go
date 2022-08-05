package cautils

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/ui"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	x509ext "github.com/google/go-attestation/x509"
	"github.com/google/go-tpm-tools/simulator"
)

func startHTTPServer(addr, token, keyAuth string) *http.Server {
	srv := &http.Server{Addr: addr}

	http.HandleFunc(fmt.Sprintf("/.well-known/acme-challenge/%s", token), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(keyAuth))
	})

	go func() {
		// returns ErrServerClosed on graceful close
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// NOTE: there is a chance that next line won't have time to run,
			// as main() doesn't wait for this goroutine to stop. don't use
			// code with race conditions like these for production. see post
			// comments below on more discussion on how to handle this.
			ui.Printf("\nListenAndServe(): %s\n", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

type issueMode interface {
	Run() error
	Cleanup() error
}

type standaloneMode struct {
	identifier, token string
	key               *jose.JSONWebKey
	listenAddr        string
	srv               *http.Server
}

func newStandaloneMode(identifier, listenAddr, token string, key *jose.JSONWebKey) *standaloneMode {
	return &standaloneMode{
		identifier: identifier,
		listenAddr: listenAddr,
		token:      token,
		key:        key,
	}
}

func (sm *standaloneMode) Run() error {
	ui.Printf("Using Standalone Mode HTTP challenge to validate %s", sm.identifier)
	keyAuth, err := acme.KeyAuthorization(sm.token, sm.key)
	if err != nil {
		return errors.Wrap(err, "error generating ACME key authorization")
	}
	sm.srv = startHTTPServer(sm.listenAddr, sm.token, keyAuth)
	return nil
}

func (sm *standaloneMode) Cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	return errors.Wrap(sm.srv.Shutdown(ctx), "error gracefully shutting down server")
}

type webrootMode struct {
	dir, token, identifier string
	key                    *jose.JSONWebKey
}

func newWebrootMode(dir, token, identifier string, key *jose.JSONWebKey) *webrootMode {
	return &webrootMode{
		dir:        dir,
		token:      token,
		identifier: identifier,
		key:        key,
	}
}

func (wm *webrootMode) Run() error {
	ui.Printf("Using Webroot Mode HTTP challenge to validate %s", wm.identifier)
	keyAuth, err := acme.KeyAuthorization(wm.token, wm.key)
	if err != nil {
		return errors.Wrap(err, "error generating ACME key authorization")
	}
	_, err = os.Stat(wm.dir)
	switch {
	case os.IsNotExist(err):
		return errors.Errorf("webroot directory %s does not exist", wm.dir)
	case err != nil:
		return errors.Wrapf(err, "error checking for directory %s", wm.dir)
	}

	// Use 0755 and 0644 (rather than 0700 and 0600) for directory and file
	// respectively because the process running the file server, and therefore
	// reading/serving the file, may be owned by a different user than
	// the one running the `step` command that will write the file.
	chPath := fmt.Sprintf("%s/.well-known/acme-challenge", wm.dir)
	if _, err = os.Stat(chPath); os.IsNotExist(err) {
		if err = os.MkdirAll(chPath, 0755); err != nil {
			return errors.Wrapf(err, "error creating directory path %s", chPath)
		}
	}

	return errors.Wrapf(os.WriteFile(fmt.Sprintf("%s/%s", chPath, wm.token), []byte(keyAuth), 0644),
		"error writing key authorization file %s", chPath+wm.token)
}

func (wm *webrootMode) Cleanup() error {
	return errors.Wrap(os.Remove(fmt.Sprintf("%s/.well-known/acme-challenge/%s",
		wm.dir, wm.token)), "error removing ACME challenge file")
}

func serveAndValidateHTTPChallenge(ctx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string) error {
	var mode issueMode
	if ctx.Bool("standalone") {
		mode = newStandaloneMode(identifier, ctx.String("http-listen"), ch.Token, ac.Key)
	} else {
		mode = newWebrootMode(ctx.String("webroot"), ch.Token, identifier, ac.Key)
	}
	if err := mode.Run(); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return err
	}
	ui.Printf(" .") // Indicates passage of time.

	if err := ac.ValidateChallenge(ch.URL, nil); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return errors.Wrapf(err, "error validating ACME Challenge at %s", ch.URL)
	}
	var (
		isValid = false
		vch     *acme.Challenge
		err     error
	)
	time.Sleep(time.Second) // brief sleep to allow server time to validate challenge.
	for attempts := 0; attempts < 10; attempts++ {
		vch, err = ac.GetChallenge(ch.URL)
		if err != nil {
			ui.Printf(" Error!\n\n")
			mode.Cleanup()
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
		mode.Cleanup()
		return errors.Errorf("Unable to validate challenge: %+v", vch)
	}
	if err := mode.Cleanup(); err != nil {
		return err
	}
	ui.Printf(" done!\n")
	return nil
}

func validatePermanentIdentifierChallenge(ctx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string) error {
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

	info, err := tpm.Info()
	if err != nil {
		panic(err)
	}

	// TODO(hs): remove this output
	ui.Printf("\nTPM INFO:")
	ui.Printf("\nversion: %d", info.Version)
	ui.Printf("\ninterface: %d", info.Interface)
	ui.Printf("\nmanufacturer: %s", info.Manufacturer)
	ui.Printf("\nvendor info: %s", info.VendorInfo)
	ui.Printf("\nfirmware version: %d.%d\n", info.FirmwareVersionMajor, info.FirmwareVersionMinor)

	data, err := keyAuthDigest(ac.Key, ch.Token)
	if err != nil {
		log.Fatal(err)
	}

	config := &attest.KeyConfig{
		//Algorithm: attest.ECDSA,
		//Size:      256,
		// TODO(hs): I had to change this to RSA to make the AK key and the cert key type check out with each other. Check if this is indeed required.
		// TODO(hs): with attest.RSA, I get an error when decoding the public key on server side:  panic: parsing public key: missing rsa signature scheme. Not sure where that has to be added ATM.
		Algorithm:      attest.RSA,
		Size:           2048, // TODO(hs): 4096 didn't work on my TPM? Look into why that's the case. Returned a TPM error; RCValue = 0x04;  value is out of range or is not correct for the context
		QualifyingData: data,
	}
	certKey, err := tpm.NewKey(ak, config)
	if err != nil {
		log.Fatal(err)
	}

	// Generate the WebAuthn attestation statement.
	payload, err := attestationStatement(certKey, akCert)
	if err != nil {
		log.Fatal(err)
	}

	req := struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(payload),
	}

	if err := ac.ValidateChallenge(ch.URL, req); err != nil {
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
	// 	return err
	// }
	ui.Printf(" done!\n")

	return nil
}

func akCert(ak *attest.AK, identifier string) ([]byte, error) {
	akRootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// akRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	return nil, err
	// }
	akRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	permID := x509ext.PermanentIdentifier{
		IdentifierValue: identifier,
		Assigner:        asn1.ObjectIdentifier{0, 1, 2, 3, 4},
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
	akPub, err := attest.ParseAKPublic(attest.TPMVersion20, ak.AttestationParameters().Public)
	if err != nil {
		return nil, err
	}
	akCert, err := x509.CreateCertificate(rand.Reader, akTemplate, akRootTemplate, akPub.Public, akRootKey)
	if err != nil {
		return nil, err
	}
	return akCert, nil
}

type AttestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

func attestationStatement(key *attest.Key, akCert []byte) ([]byte, error) {
	params := key.CertificationParameters()

	obj := &AttestationObject{
		Format: "tpm", // TODO: `tpm` is the value used in WebAuthn for generic TPM attestation; is that what we want in `step` CLI too?
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      int64(-257), // AlgRS256
			"x5c":      []interface{}{akCert},
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

type simulatorChannel struct {
	io.ReadWriteCloser
}

func (simulatorChannel) MeasurementLog() ([]byte, error) {
	return nil, errors.New("not implemented")
}

// Default to not using the TPM simulator
var UseSimulator bool = false

func tpmInit(identifier string) (*attest.TPM, *attest.AK, []byte, error) {
	config := &attest.OpenConfig{}
	useSimulator := &UseSimulator
	if *useSimulator {
		sim, err := simulator.Get() // TODO(hs): remove simulator support? Would be nice if we don't have to rely on it, except for tests
		if err != nil {
			return nil, nil, nil, err
		}
		config.CommandChannel = simulatorChannel{sim}
	}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return nil, nil, nil, err
	}
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	akCert, err := akCert(ak, identifier)
	if err != nil {
		return nil, nil, nil, err
	}
	return tpm, ak, akCert, nil
}

// Borrowed from:
// https://github.com/golang/crypto/blob/master/acme/acme.go#L748
func keyAuthDigest(jwk *jose.JSONWebKey, token string) ([]byte, error) {
	th, err := jwk.Thumbprint(crypto.SHA256) // TODO(hs): verify this is the correct thumbprint
	// jwk, err := jwkEncode(pub)
	// if err != nil {
	// 	return "", err
	// }
	// b := sha256.Sum256([]byte(jwk))
	// return base64.RawURLEncoding.EncodeToString(b[:]), nil
	// th, err := stdacme.JWKThumbprint(pub)
	// if err != nil {
	// 	return nil, err
	// }
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", token, th)))
	return digest[:], err
}

func authorizeOrder(ctx *cli.Context, ac *ca.ACMEClient, o *acme.Order) error {
	for _, azURL := range o.AuthorizationURLs {
		az, err := ac.GetAuthz(azURL)
		if err != nil {
			return errors.Wrapf(err, "error retrieving ACME Authz at %s", azURL)
		}

		ident := az.Identifier.Value
		if az.Wildcard {
			ident = "*." + ident
		}

		chValidated := false
		for _, ch := range az.Challenges {
			// TODO: Allow other types of challenges (not just http); at least TLS-ALPN-01
			if ch.Type == "http-01" {
				if err := serveAndValidateHTTPChallenge(ctx, ac, ch, ident); err != nil {
					return err
				}
				chValidated = true
				break
			}
			if ch.Type == "device-attest-01" {
				if err := validatePermanentIdentifierChallenge(ctx, ac, ch, ident); err != nil {
					return err
				}
				chValidated = true
				break
			}
		}
		if !chValidated {
			return errors.Errorf("unable to validate any challenges for identifier: %s", ident)
		}
	}
	return nil
}

func finalizeOrder(ac *ca.ACMEClient, o *acme.Order, csr *x509.CertificateRequest) (*acme.Order, error) {
	var (
		err              error
		ro, fo           *acme.Order
		isReady, isValid bool
	)
	ui.Printf("Waiting for Order to be 'ready' for finalization .")
	for i := 9; i >= 0; i-- {
		time.Sleep(1 * time.Second)
		ui.Printf(".")
		ro, err = ac.GetOrder(o.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving order %s", o.ID)
		}
		if ro.Status == "ready" {
			isReady = true
			ui.Printf(" done!\n")
			break
		}
	}
	if !isReady {
		ui.Printf(" Error!\n\n")
		return nil, errors.Errorf("Unable to validate order: %+v", ro)
	}

	ui.Printf("Finalizing Order .")
	if err = ac.FinalizeOrder(o.FinalizeURL, csr); err != nil {
		return nil, errors.Wrapf(err, "error finalizing order")
	}

	for i := 9; i >= 0; i-- {
		time.Sleep(1 * time.Second)
		ui.Printf(".")
		fo, err = ac.GetOrder(o.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving order %s", o.ID)
		}
		if fo.Status == "valid" {
			isValid = true
			ui.Printf(" done!\n")
			break
		}
	}
	if !isValid {
		ui.Printf(" Error!\n\n")
		return nil, errors.Errorf("Unable to finalize order: %+v", fo)
	}

	return fo, nil
}

func validateSANsForACME(sans []string) ([]string, []net.IP, error) {
	dnsNames, ips, emails, uris := splitSANs(sans)
	if len(emails) > 0 || len(uris) > 0 {
		return nil, nil, errors.New("Email Address and URI SANs are not supported for ACME flow")
	}
	for _, dns := range dnsNames {
		if strings.Contains(dns, "*") {
			return nil, nil, errors.Errorf("wildcard dnsnames (%s) require dns validation, "+
				"which is currently not implemented in this client", dns)
		}
	}
	return dnsNames, ips, nil
}

type acmeFlowOp func(*acmeFlow) error

func withProvisionerName(name string) acmeFlowOp {
	return func(af *acmeFlow) error {
		af.provisionerName = name
		return nil
	}
}

func withCSR(csr *x509.CertificateRequest) acmeFlowOp {
	return func(af *acmeFlow) error {
		af.csr = csr
		af.subject = csr.Subject.CommonName
		af.sans = csr.DNSNames
		for _, ip := range csr.IPAddresses {
			af.sans = append(af.sans, ip.String())
		}
		return nil
	}
}

func withSubjectSANs(sub string, sans []string) acmeFlowOp {
	return func(af *acmeFlow) error {
		af.subject = sub
		af.sans = sans
		return nil
	}
}

type acmeFlow struct {
	ctx             *cli.Context
	provisionerName string
	csr             *x509.CertificateRequest
	priv            interface{}
	subject         string
	sans            []string
	acmeDir         string
}

func newACMEFlow(ctx *cli.Context, ops ...acmeFlowOp) (*acmeFlow, error) {
	// Offline mode is not supported for ACME protocol
	if ctx.Bool("offline") {
		return nil, errors.New("offline mode and ACME are mutually exclusive")
	}
	// One of --standalone or --webroot must be selected for use with ACME protocol.
	isStandalone, webroot := ctx.Bool("standalone"), ctx.String("webroot")
	switch {
	case isStandalone && len(webroot) > 0:
		return nil, errs.MutuallyExclusiveFlags(ctx, "standalone", "webroot")
	case !isStandalone && webroot == "":
		if err := ctx.Set("standalone", "true"); err != nil {
			return nil, errors.Wrap(err, "error setting 'standalone' value in cli ctx")
		}
	}

	af := new(acmeFlow)
	for _, op := range ops {
		if err := op(af); err != nil {
			return nil, err
		}
	}
	if len(af.sans) == 0 {
		af.sans = []string{af.subject}
	}

	af.ctx = ctx

	af.acmeDir = ctx.String("acme")
	if af.acmeDir == "" {
		caURL, err := flags.ParseCaURL(ctx)
		if err != nil {
			return nil, err
		}
		if af.provisionerName == "" {
			return nil, errors.New("acme flow expected provisioner ID")
		}
		af.acmeDir = fmt.Sprintf("%s/acme/%s/directory", caURL, af.provisionerName)
	}

	return af, nil
}

func (af *acmeFlow) getClientTruststoreOption(mergeRootCAs bool) (ca.ClientOption, error) {
	root := ""
	if af.ctx.IsSet("root") {
		root = af.ctx.String("root")
		// If there's an error reading the local root ca, ignore the error and use the system store
	} else if _, err := os.Stat(pki.GetRootCAPath()); err == nil {
		root = pki.GetRootCAPath()
	}

	// 1. Merge local RootCA with system store
	if mergeRootCAs && len(root) > 0 {
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		cert, err := os.ReadFile(root)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read local root ca")
		}

		if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
			return nil, errors.New("failed to append local root ca to system cert pool")
		}

		return ca.WithTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}), nil
	}

	// Use local Root CA only
	if len(root) > 0 {
		return ca.WithRootFile(root), nil
	}

	// Use system store only
	return ca.WithTransport(http.DefaultTransport), nil
}

func (af *acmeFlow) GetCertificate() ([]*x509.Certificate, error) {
	dnsNames, ips, err := validateSANsForACME(af.sans)
	if err != nil {
		return nil, err
	}

	var idents []acme.Identifier
	for _, dns := range dnsNames {
		idents = append(idents, acme.Identifier{
			Type:  "dns",
			Value: dns,
		})
	}
	for _, ip := range ips {
		idents = append(idents, acme.Identifier{
			Type:  "ip",
			Value: ip.String(),
		})
	}

	permanentIdentifiers := af.ctx.StringSlice("permanent-identifier")
	for _, pi := range permanentIdentifiers {
		idents = append(idents, acme.Identifier{
			Type:  "permanent-identifier",
			Value: pi,
		})
	}

	var (
		orderPayload []byte
		clientOps    []ca.ClientOption
	)

	ops, err := af.getClientTruststoreOption(af.ctx.IsSet("acme"))
	if err != nil {
		return nil, err
	}

	clientOps = append(clientOps, ops)

	if strings.Contains(af.acmeDir, "letsencrypt") {
		// LetsEncrypt does not support NotBefore and NotAfter attributes in orders.
		if af.ctx.IsSet("not-before") || af.ctx.IsSet("not-after") {
			return nil, errors.New("LetsEncrypt public CA does not support NotBefore/NotAfter " +
				"attributes for certificates. Instead, each certificate has a default lifetime of 3 months.")
		}
		// LetsEncrypt requires that the Common Name of the Certificate also be
		// represented as a DNSName in the SAN extension, and therefore must be
		// authorized as part of the ACME order.
		hasSubject := false
		for _, n := range idents {
			if n.Value == af.subject {
				hasSubject = true
			}
		}
		if !hasSubject {
			dnsNames = append(dnsNames, af.subject)
			idents = append(idents, acme.Identifier{
				Type:  "dns",
				Value: af.subject,
			})
		}
		orderPayload, err = json.Marshal(struct {
			Identifiers []acme.Identifier
		}{Identifiers: idents})
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling new letsencrypt order request")
		}
	} else {
		// parse times or durations
		nbf, naf, err := flags.ParseTimeDuration(af.ctx)
		if err != nil {
			return nil, err
		}

		// check if the list of identifiers for which to
		// request a certificate already contains the subject
		hasSubject := false
		for _, n := range idents {
			if n.Value == af.subject {
				hasSubject = true
			}
		}
		// if the subject is not yet included in the slice
		// of identifiers, it is added to either the DNS names
		// or IP addresses slice and the corresponding type of
		// identifier is added to the slice of identifers.
		if !hasSubject {
			if ip := net.ParseIP(af.subject); ip != nil {
				ips = append(ips, ip)
				idents = append(idents, acme.Identifier{
					Type:  "ip",
					Value: ip.String(),
				})
			} else {
				dnsNames = append(dnsNames, af.subject)
				idents = append(idents, acme.Identifier{
					Type:  "dns",
					Value: af.subject,
				})
			}
		}
		nor := acmeAPI.NewOrderRequest{
			Identifiers: idents,
			NotAfter:    naf.Time(),
			NotBefore:   nbf.Time(),
		}
		orderPayload, err = json.Marshal(nor)
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling new order request")
		}
	}

	ac, err := ca.NewACMEClient(af.acmeDir, af.ctx.StringSlice("contact"), clientOps...)
	if err != nil {
		return nil, errors.Wrapf(err, "error initializing ACME client with server %s", af.acmeDir)
	}

	o, err := ac.NewOrder(orderPayload)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating new ACME order")
	}

	if err := authorizeOrder(af.ctx, ac, o); err != nil {
		return nil, err
	}

	if af.csr == nil {
		insecure := af.ctx.Bool("insecure")
		kty, crv, size, err := utils.GetKeyDetailsFromCLI(af.ctx, insecure, "kty", "curve", "size")
		if err != nil {
			return nil, err
		}
		af.priv, err = keys.GenerateKey(kty, crv, size)
		if err != nil {
			return nil, errors.Wrap(err, "error generating private key")
		}

		// prepare the certificate request
		_csr := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: af.subject,
			},
			DNSNames:    dnsNames,
			IPAddresses: ips,
		}

		// process PermanentIdentifiers and add them to the certificate request
		permanentIdentifiers := af.ctx.StringSlice("permanent-identifier")
		if len(permanentIdentifiers) > 0 {
			san := &x509ext.SubjectAltName{
				PermanentIdentifiers: []x509ext.PermanentIdentifier{},
			}
			for _, identifier := range permanentIdentifiers {
				permID := x509ext.PermanentIdentifier{
					IdentifierValue: identifier,
					Assigner:        asn1.ObjectIdentifier{0, 1, 2, 3, 4},
				}
				san.PermanentIdentifiers = append(san.PermanentIdentifiers, permID)
			}
			ext, err := x509ext.MarshalSubjectAltName(san)
			if err != nil {
				return nil, err
			}
			_csr.ExtraExtensions = []pkix.Extension{ext}
		}

		var csrBytes []byte
		csrBytes, err = x509.CreateCertificateRequest(rand.Reader, _csr, af.priv)
		if err != nil {
			return nil, errors.Wrap(err, "error creating certificate request")
		}
		af.csr, err = x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificate request")
		}
	}

	fo, err := finalizeOrder(ac, o, af.csr)
	if err != nil {
		return nil, err
	}

	leaf, chain, err := ac.GetCertificate(fo.CertificateURL)
	if err != nil {
		return nil, errors.Wrapf(err, "error getting certificate")
	}
	return append([]*x509.Certificate{leaf}, chain...), nil
}

func writeCert(chain []*x509.Certificate, certFile string) error {
	var certBytes = []byte{}
	for _, c := range chain {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}

	if err := utils.WriteFile(certFile, certBytes, 0600); err != nil {
		return errs.FileError(err, certFile)
	}
	return nil
}
