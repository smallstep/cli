package cautils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/cryptoutil"
	"github.com/smallstep/cli/utils"
)

func startHTTPServer(addr, token, keyAuth string) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 15 * time.Second,
	}

	http.HandleFunc(fmt.Sprintf("/.well-known/acme-challenge/%s", token), func(w http.ResponseWriter, _ *http.Request) {
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

	// NOTE: Use 0755 and 0644 (rather than 0700 and 0600) for directory and file
	// respectively because the process running the file server, and therefore
	// reading/serving the file, may be owned by a different user than
	// the one running the `step` command that will write the file.
	chPath := fmt.Sprintf("%s/.well-known/acme-challenge", wm.dir)
	if _, err = os.Stat(chPath); os.IsNotExist(err) {
		if err = os.MkdirAll(chPath, 0755); err != nil {
			return errors.Wrapf(err, "error creating directory path %s", chPath)
		}
	}

	//nolint:gosec // See note above.
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

	if err := ac.ValidateChallenge(ch.URL); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return errors.Wrapf(err, "error validating ACME Challenge at %s", ch.URL)
	}

	time.Sleep(time.Second) // brief sleep to allow server time to validate challenge.

	durationBetweenAttempts := 5 * time.Second
	if err := getChallengeStatus(ac, ch, durationBetweenAttempts); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return err
	}

	if err := mode.Cleanup(); err != nil {
		return err
	}

	ui.Printf(" done!\n")
	return nil
}

func authorizeOrder(ctx *cli.Context, ac *ca.ACMEClient, o *acme.Order, af *acmeFlow) error {
	isAttest := (ctx.String("attestation-uri") != "")
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
			// TODO: Allow other types of challenges (not just http).
			if ch.Type == "http-01" && !isAttest {
				if err := serveAndValidateHTTPChallenge(ctx, ac, ch, ident); err != nil {
					return err
				}
				chValidated = true
				break
			}
			if ch.Type == "device-attest-01" && isAttest {
				if err := doDeviceAttestation(ctx, ac, ch, ident, af); err != nil {
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

func createNewOrderRequest(ctx *cli.Context, acmeDir, subject string, sans []string) (interface{}, []string, []net.IP, error) {
	dnsNames, ips, err := validateSANsForACME(sans)
	if err != nil {
		return nil, nil, nil, err
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

	if strings.Contains(acmeDir, "letsencrypt") {
		// LetsEncrypt does not support NotBefore and NotAfter attributes in
		// orders.
		if ctx.IsSet("not-before") || ctx.IsSet("not-after") {
			return nil, nil, nil, errors.New(
				"LetsEncrypt public CA does not support NotBefore/NotAfter attributes for certificates. " +
					"Instead, each certificate has a default lifetime of 3 months.",
			)
		}

		// LetsEncrypt requires that the Common Name of the Certificate also be
		// represented as a DNSName in the SAN extension, and therefore must be
		// authorized as part of the ACME order.
		hasSubject := false
		for _, n := range idents {
			if n.Value == subject {
				hasSubject = true
			}
		}

		if !hasSubject {
			dnsNames = append(dnsNames, subject)
			idents = append(idents, acme.Identifier{
				Type:  "dns",
				Value: subject,
			})
		}

		return struct {
			Identifiers []acme.Identifier
		}{Identifiers: idents}, dnsNames, ips, nil
	}

	// parse times or durations
	nbf, naf, err := flags.ParseTimeDuration(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	// check if the list of identifiers for which to request a certificate
	// already contains the subject
	hasSubject := false
	for _, n := range idents {
		if n.Value == subject {
			hasSubject = true
		}
	}

	// if the subject is not yet included in the slice of identifiers, it is
	// added to either the DNS names or IP addresses slice and the corresponding
	// type of identifier is added to the slice of identifiers.
	if !hasSubject {
		if ip := net.ParseIP(subject); ip != nil {
			ips = append(ips, ip)
			idents = append(idents, acme.Identifier{
				Type:  "ip",
				Value: ip.String(),
			})
		} else {
			dnsNames = append(dnsNames, subject)
			idents = append(idents, acme.Identifier{
				Type:  "dns",
				Value: subject,
			})
		}
	}

	return acmeAPI.NewOrderRequest{
		Identifiers: idents,
		NotAfter:    naf.Time(),
		NotBefore:   nbf.Time(),
	}, dnsNames, ips, nil
}

type attestationPayload struct {
	AttObj string `json:"attObj"`
}

type attestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

// doDeviceAttestation performs `device-attest-01` challenge validation.
func doDeviceAttestation(clictx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string, af *acmeFlow) error {
	// TODO(hs): make TPM flow work with CreateAttestor()/Attest() too
	attestationURI := clictx.String("attestation-uri")
	if strings.HasPrefix(attestationURI, "tpmkms:") {
		return doTPMAttestation(clictx, ac, ch, identifier, af)
	}

	attestor, err := cryptoutil.CreateAttestor("", attestationURI)
	if err != nil {
		return err
	}
	pemData, err := attestor.Attest()
	if err != nil {
		return err
	}

	data, err := acme.KeyAuthorization(ch.Token, ac.Key)
	if err != nil {
		return errors.Wrap(err, "error generating ACME key authorization")
	}

	var alg int64
	var digest []byte
	var opts crypto.SignerOpts
	switch k := attestor.Public().(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("unsupported elliptic curve %s", k.Curve)
		}
		alg = -7 // ES256
		opts = crypto.SHA256
		sum := sha256.Sum256([]byte(data))
		digest = sum[:]
	case *rsa.PublicKey:
		// TODO(mariano): support for PS256 (-37)
		alg = -257 // RS256
		opts = crypto.SHA256
		sum := sha256.Sum256([]byte(data))
		digest = sum[:]
	case ed25519.PublicKey:
		alg = -8 // EdDSA
		opts = crypto.Hash(0)
		digest = []byte(data)
	default:
		return fmt.Errorf("unsupported public key type %T", k)
	}

	// Sign proves possession of private key. Per recommendation at
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types, we use
	// CBOR to encode the signature.
	sig, err := attestor.Sign(rand.Reader, digest, opts)
	if err != nil {
		return errors.Wrap(err, "error signing key authorization")
	}
	sig, err = cbor.Marshal(sig)
	if err != nil {
		return errors.Wrap(err, "error marshaling signature")
	}

	certs, err := pemutil.ParseCertificateBundle(pemData)
	if err != nil {
		return err
	}

	x5c := make([][]byte, len(certs))
	for i, c := range certs {
		x5c[i] = c.Raw
	}

	// step format is based on the "packed" format described in
	// https://w3c.github.io/webauthn/#sctn-attestation but with the authData
	// omitted as described in the device-attest-01 RFC.
	obj := &attestationObject{
		Format: "step",
		AttStatement: map[string]interface{}{
			"alg": alg,
			"sig": sig,
			"x5c": x5c,
		},
	}

	b, err := cbor.Marshal(obj)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(attestationPayload{
		AttObj: base64.RawURLEncoding.EncodeToString(b),
	})
	if err != nil {
		return fmt.Errorf("error marshaling payload: %w", err)
	}

	ui.Printf("Using Device Attestation challenge to validate %q", identifier)
	ui.Printf(" .") // Indicates passage of time.

	if err := ac.ValidateWithPayload(ch.URL, payload); err != nil {
		ui.Printf(" Error!\n\n")
		return errors.Wrapf(err, "error validating ACME Challenge at %s", ch.URL)
	}

	durationBetweenAttempts := 2 * time.Second
	if err := getChallengeStatus(ac, ch, durationBetweenAttempts); err != nil {
		ui.Printf(" Error!\n\n")
		return err
	}

	ui.Printf(" done!\n")
	return nil
}

// getChallengeStatus retrieves the ACME Challenge status from the CA. It
// will retry this 10 times if the status is not `invalid` or `valid`. This
// is the case, for example, when the CA hasn't been able to connect to the
// HTTP endpoint for some reason.
func getChallengeStatus(ac *ca.ACMEClient, ch *acme.Challenge, durationBetweenAttempts time.Duration) error {
	var (
		isValid = false
		vch     *acme.Challenge
		err     error
	)
	for attempts := 0; attempts < 10; attempts++ {
		vch, err = ac.GetChallenge(ch.URL) // TODO(hs): GetChallenge should return an ACME GetChallenge client response type; not core acme.Challenge type (for safety)
		if err != nil {
			return errors.Wrapf(err, "error retrieving ACME Challenge at %s", ch.URL)
		}
		// break early if challenge validation failed. Due to nature of the `device-attest-01`
		// challenge validation, this will (currently) happen immediately, as the validation is
		// performed synchronously by the CA when the request for `ac.ValidateWithPayload` is
		// sent. For `http-01`, this is the case when the key authorization doesn't match.
		// In the (near) future we might change the way the validation is performed, so keeping
		// the retry logic intact for now.
		if vch.Status == "invalid" {
			break
		}
		if vch.Status == "valid" {
			isValid = true
			break
		}
		ui.Printf(".")
		time.Sleep(durationBetweenAttempts)
	}
	if !isValid {
		return errors.New(extractDetailedErrorMessageFromChallenge(vch))
	}
	return nil
}

// extractDetailedErrorMessageFromChallenge extracts error details from an
// ACME Challenge if the server captured an error when validating it. When
// the ACME Error has one or more Subproblems, the details will be extracted
// from those. Otherwise, the main Error detail will be used. In case the
// server did not return an Error for the Challenge, a textual representation
// of the Challenge is printed as fallback.
func extractDetailedErrorMessageFromChallenge(vch *acme.Challenge) string {
	switch {
	case vch.Error == nil:
		// fallback to original error message
		return fmt.Sprintf("Unable to validate challenge: %+v", vch)
	case len(vch.Error.Subproblems) == 1:
		if detail := vch.Error.Subproblems[0].Detail; detail != "" {
			return fmt.Sprintf("Unable to validate challenge: %s", detail)
		}
		fallthrough // subproblem detail empty; fallthrough to the error
	case len(vch.Error.Subproblems) > 1:
		details := make([]string, len(vch.Error.Subproblems))
		for i, s := range vch.Error.Subproblems {
			if s.Detail == "" {
				details[i] = fmt.Sprintf("%+v", s)
			} else {
				details[i] = s.Detail
			}
		}
		return fmt.Sprintf("Unable to validate challenge: %s", strings.Join(details, "; "))
	case vch.Error.Detail == "":
		// fallback to original error message
		return fmt.Sprintf("Unable to validate challenge: %+v", vch)
	default:
		return fmt.Sprintf("Unable to validate challenge: %s", vch.Error.Detail)
	}
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
	tpmSigner       crypto.Signer
}

func newACMEFlow(ctx *cli.Context, ops ...acmeFlowOp) (*acmeFlow, error) {
	// Offline mode is not supported for ACME protocol
	if ctx.Bool("offline") {
		return nil, errors.New("offline mode and ACME are mutually exclusive")
	}
	// One of --standalone or --webroot must be selected for use with ACME protocol.
	isStandalone, webroot := ctx.Bool("standalone"), ctx.String("webroot")
	switch {
	case isStandalone && webroot != "":
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
	if mergeRootCAs && root != "" {
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

		return ca.WithTransport(&http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		}), nil
	}

	// Use local Root CA only
	if root != "" {
		return ca.WithRootFile(root), nil
	}

	// Use system store only
	return ca.WithTransport(http.DefaultTransport), nil
}

func (af *acmeFlow) GetCertificate() ([]*x509.Certificate, error) {
	var (
		err             error
		newOrderRequest interface{}
		dnsNames        []string
		ips             []net.IP
	)

	attestationURI := af.ctx.String("attestation-uri")
	if attestationURI == "" {
		newOrderRequest, dnsNames, ips, err = createNewOrderRequest(af.ctx, af.acmeDir, af.subject, af.sans)
		if err != nil {
			return nil, err
		}
	} else {
		// parse times or durations
		nbf, naf, err := flags.ParseTimeDuration(af.ctx)
		if err != nil {
			return nil, err
		}

		// We currently do not accept other SANs with attestation certificates.
		newOrderRequest = acmeAPI.NewOrderRequest{
			Identifiers: []acme.Identifier{{
				Type:  "permanent-identifier",
				Value: af.subject,
			}},
			NotBefore: nbf.Time(),
			NotAfter:  naf.Time(),
		}
	}

	orderPayload, err := json.Marshal(newOrderRequest)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling order request")
	}

	ops, err := af.getClientTruststoreOption(af.ctx.IsSet("acme"))
	if err != nil {
		return nil, err
	}

	ac, err := ca.NewACMEClient(af.acmeDir, af.ctx.StringSlice("contact"), ops)
	if err != nil {
		return nil, errors.Wrapf(err, "error initializing ACME client with server %s", af.acmeDir)
	}

	o, err := ac.NewOrder(orderPayload)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating new ACME order")
	}

	if err := authorizeOrder(af.ctx, ac, o, af); err != nil {
		return nil, err
	}

	if af.csr == nil {
		var signer crypto.Signer
		var template *x509.CertificateRequest
		switch {
		case attestationURI == "":
			insecure := af.ctx.Bool("insecure")
			kty, crv, size, err := utils.GetKeyDetailsFromCLI(af.ctx, insecure, "kty", "curve", "size")
			if err != nil {
				return nil, err
			}
			signer, err = keyutil.GenerateSigner(kty, crv, size)
			if err != nil {
				return nil, errors.Wrap(err, "error generating private key")
			}
			af.priv = signer
			template = &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: af.subject,
				},
				DNSNames:    dnsNames,
				IPAddresses: ips,
			}
		case af.tpmSigner != nil:
			signer = af.tpmSigner
			template = &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: af.subject,
				},
				// TODO(hs): add PermanentIdentifier extension?
				// TODO(hs): add SKAE extension?
			}
		default:
			signer, err = cryptoutil.CreateSigner(attestationURI, attestationURI)
			if err != nil {
				return nil, err
			}
			template = &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: af.subject,
				},
			}
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
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

	fullChain := append([]*x509.Certificate{leaf}, chain...)

	// TODO: refactor this to be cleaner by passing the TPM and/or key around
	// instead of creating a new instance.
	if af.tpmSigner != nil {
		attestationURI := af.ctx.String("attestation-uri")
		tpmStorageDirectory := af.ctx.String("tpm-storage-directory")

		keyName, attURI, err := parseTPMAttestationURI(attestationURI)
		if err != nil {
			return nil, fmt.Errorf("failed parsing --attestation-uri: %w", err)
		}

		tpmOpts := []tpm.NewTPMOption{
			tpm.WithStore(tpmstorage.NewDirstore(tpmStorageDirectory)),
		}
		if device := attURI.Get("device"); device != "" {
			tpmOpts = append(tpmOpts, tpm.WithDeviceName(device))
		}

		t, err := tpm.New(tpmOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed initializing TPM: %w", err)
		}

		ctx := tpm.NewContext(context.Background(), t)
		key, err := t.GetKey(ctx, keyName)
		if err != nil {
			return nil, fmt.Errorf("failed getting TPM key: %w", err)
		}
		if err = key.SetCertificateChain(ctx, fullChain); err != nil {
			return nil, fmt.Errorf("failed storing certificate with TPM key: %w", err)
		}
	}

	return fullChain, nil
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
