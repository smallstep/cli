package cautils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/internal/cryptoutil"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
)

// TokenGenerator is a helper used to generate different types of tokens used in
// the CA.
type TokenGenerator struct {
	kid, iss, aud       string
	root                string
	notBefore, notAfter time.Time
	jwk                 *jose.JSONWebKey
}

// NewTokenGenerator initializes a new token generator with the common fields.
func NewTokenGenerator(kid, iss, aud, root string, notBefore, notAfter time.Time, jwk *jose.JSONWebKey) *TokenGenerator {
	return &TokenGenerator{
		kid:       kid,
		iss:       iss,
		aud:       aud,
		root:      root,
		notBefore: notBefore,
		notAfter:  notAfter,
		jwk:       jwk,
	}
}

// Token generates a generic token with the given subject and options.
func (t *TokenGenerator) Token(sub string, opts ...token.Options) (string, error) {
	// A random jwt id will be used to identify duplicated tokens
	jwtID, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return "", err
	}

	tokOptions := []token.Options{
		token.WithJWTID(jwtID),
		token.WithKid(t.kid),
		token.WithIssuer(t.iss),
		token.WithAudience(t.aud),
	}
	if t.root != "" {
		tokOptions = append(tokOptions, token.WithRootCA(t.root))
	}

	// Add custom options
	tokOptions = append(tokOptions, opts...)

	// Add token validity
	notBefore, notAfter := t.notBefore, t.notAfter
	if !notBefore.IsZero() || !notAfter.IsZero() {
		if notBefore.IsZero() {
			notBefore = time.Now()
		}
		if notAfter.IsZero() {
			notAfter = notBefore.Add(token.DefaultValidity)
		}
		tokOptions = append(tokOptions, token.WithValidity(notBefore, notAfter))
	}

	tok, err := provision.New(sub, tokOptions...)
	if err != nil {
		return "", err
	}

	return tok.SignedString(t.jwk.Algorithm, t.jwk.Key)
}

// SignToken generates a X.509 certificate signing token. If sans is empty, we
// will use the subject (common name) as the only SAN.
func (t *TokenGenerator) SignToken(sub string, sans []string, opts ...token.Options) (string, error) {
	if len(sans) == 0 {
		sans = []string{sub}
	}
	opts = append(opts, token.WithSANS(sans))

	// Tie certificate request to the token used in the JWK and X5C provisioners
	if sharedContext.CertificateRequest != nil {
		opts = append(opts, token.WithFingerprint(sharedContext.CertificateRequest))
	} else if sharedContext.ConfirmationFingerprint != "" {
		opts = append(opts, token.WithConfirmationFingerprint(sharedContext.ConfirmationFingerprint))
	}

	return t.Token(sub, opts...)
}

// RevokeToken generates a X.509 certificate revoke token.
func (t *TokenGenerator) RevokeToken(sub string, opts ...token.Options) (string, error) {
	return t.Token(sub, opts...)
}

// SignSSHToken generates a SSH certificate signing token.
func (t *TokenGenerator) SignSSHToken(sub, certType string, principals []string, notBefore, notAfter provisioner.TimeDuration, opts ...token.Options) (string, error) {
	opts = append([]token.Options{token.WithSSH(provisioner.SignSSHOptions{
		CertType:    certType,
		KeyID:       sub,
		Principals:  principals,
		ValidAfter:  notBefore,
		ValidBefore: notAfter,
	})}, opts...)

	return t.Token(sub, opts...)
}

// generateOIDCToken performs the necessary protocol to retrieve an OIDC token
// using a configured provisioner.
func generateOIDCToken(ctx *cli.Context, p *provisioner.OIDC) (string, error) {
	args := []string{"oauth", "--oidc", "--bare",
		"--provider", p.ConfigurationEndpoint,
		"--client-id", p.ClientID, "--client-secret", p.ClientSecret}
	if len(p.Scopes) != 0 {
		for _, keyval := range p.Scopes {
			args = append(args, "--scope", keyval)
		}
	}
	if len(p.AuthParams) != 0 {
		for _, keyval := range p.AuthParams {
			args = append(args, "--auth-param", keyval)
		}
	}
	if ctx.Bool("console") {
		args = append(args, "--console")
	}
	if p.ListenAddress != "" && os.Getenv("STEP_LISTEN") == "" {
		args = append(args, "--listen", p.ListenAddress)
	}
	out, err := exec.Step(args...)
	if err != nil {
		return "", fmt.Errorf(`error generating OIDC token: exec "step oauth" failed`)
	}
	return strings.TrimSpace(string(out)), nil
}

type tokenAttrs struct {
	subject                     string
	root                        string
	caURL                       string
	audience                    string
	issuer                      string
	kid                         string
	sans                        []string
	notBefore, notAfter         time.Time
	certNotBefore, certNotAfter provisioner.TimeDuration
}

func generateK8sSAToken(ctx *cli.Context) (string, error) {
	path := ctx.String("k8ssa-token-path")
	if path == "" {
		path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	tokBytes, err := os.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(err, "error reading kubernetes service account token")
	}
	return string(tokBytes), nil
}

func generateX5CToken(ctx *cli.Context, p *provisioner.X5C, tokType int, tokAttrs tokenAttrs) (string, error) {
	x5cCertFile := ctx.String("x5c-cert")
	x5cKeyFile := ctx.String("x5c-key")
	x5cChainFiles := ctx.StringSlice("x5c-chain")
	kmsURI := ctx.String("kms")

	if x5cCertFile == "" {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "X5C", "x5c-cert")
	}
	if x5cKeyFile == "" {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "X5C", "x5c-key")
	}

	var jwk *jose.JSONWebKey
	var err error

	var opts []pemutil.Options
	if passOpt := getProvisionerPasswordPEMOption(ctx); passOpt != nil {
		opts = append(opts, passOpt)
	}

	var kmsSigner crypto.Signer
	kmsSigner, err = cryptoutil.CreateSigner(kmsURI, x5cKeyFile, opts...)
	if err != nil {
		return "", err
	}

	joseSigner := jose.NewOpaqueSigner(kmsSigner)

	alg, err := getSigningAlgorithm(kmsSigner.Public())
	if err != nil {
		return "", err
	}

	jwk = &jose.JSONWebKey{
		Key:       joseSigner,
		KeyID:     x5cKeyFile,
		Algorithm: alg,
	}

	tokenGen := NewTokenGenerator(jwk.KeyID, p.Name,
		fmt.Sprintf("%s#%s", tokAttrs.audience, p.GetIDForToken()), tokAttrs.root,
		tokAttrs.notBefore, tokAttrs.notAfter, jwk)

	var tokenOpts []token.Options
	x5cCerts, err := cryptoutil.LoadCertificate(kmsURI, x5cCertFile)
	if err != nil {
		return "", fmt.Errorf("could not load x5c certificate: %w", err)
	}

	for _, chainPath := range x5cChainFiles {
		x5cChainCerts, err := cryptoutil.LoadCertificate(kmsURI, chainPath)
		if err != nil {
			return "", fmt.Errorf("could not load x5c chain certificate %s: %w", chainPath, err)
		}
		x5cCerts = append(x5cCerts, x5cChainCerts...)
	}

	if ctx.Bool("x5c-insecure") {
		tokenOpts = append(tokenOpts, token.WithX5CInsecureCerts(x5cCerts, jwk.Key))
	} else {
		tokenOpts = append(tokenOpts, token.WithX5CCerts(x5cCerts, jwk.Key))
	}

	switch tokType {
	case SignType:
		return tokenGen.SignToken(tokAttrs.subject, tokAttrs.sans, tokenOpts...)
	case RevokeType:
		return tokenGen.RevokeToken(tokAttrs.subject, tokenOpts...)
	case SSHUserSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHUserCert, tokAttrs.sans,
			tokAttrs.certNotBefore, tokAttrs.certNotAfter, tokenOpts...)
	case SSHHostSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHHostCert, tokAttrs.sans,
			tokAttrs.certNotBefore, tokAttrs.certNotAfter, tokenOpts...)
	default:
		return tokenGen.Token(tokAttrs.subject, tokenOpts...)
	}
}

func generateNebulaToken(ctx *cli.Context, p *provisioner.Nebula, tokType int, tokAttrs tokenAttrs) (string, error) {
	certFile := ctx.String("nebula-cert")
	keyFile := ctx.String("nebula-key")
	if certFile == "" {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "Nebula", "nebula-cert")
	}
	if keyFile == "" {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "Nebula", "nebula-key")
	}

	// Get private key from given key file, nebula CAs uses ed25519 keys while
	// nebula leafs uses X25519 keys.
	jwk, err := jose.ReadKey(keyFile)
	if err != nil {
		return "", err
	}

	key := jwk.Key

	tokenGen := NewTokenGenerator(jwk.KeyID, p.Name,
		fmt.Sprintf("%s#%s", tokAttrs.audience, p.GetIDForToken()), tokAttrs.root,
		tokAttrs.notBefore, tokAttrs.notAfter, jwk)
	switch tokType {
	case SignType:
		return tokenGen.SignToken(tokAttrs.subject, tokAttrs.sans, token.WithNebulaCert(certFile, key))
	case RevokeType:
		return tokenGen.RevokeToken(tokAttrs.subject, token.WithNebulaCert(certFile, key))
	case SSHUserSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHUserCert, tokAttrs.sans,
			tokAttrs.certNotBefore, tokAttrs.certNotAfter, token.WithNebulaCert(certFile, key))
	case SSHHostSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHHostCert, tokAttrs.sans,
			tokAttrs.certNotBefore, tokAttrs.certNotAfter, token.WithNebulaCert(certFile, key))
	default:
		return tokenGen.Token(tokAttrs.subject, token.WithNebulaCert(certFile, key))
	}
}

func generateSSHPOPToken(ctx *cli.Context, p *provisioner.SSHPOP, tokType int, tokAttrs tokenAttrs) (string, error) {
	sshPOPCertFile := ctx.String("sshpop-cert")
	sshPOPKeyFile := ctx.String("sshpop-key")
	if sshPOPCertFile == "" {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "SSHPOP", "sshpop-cert")
	}
	if sshPOPKeyFile == "" {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "SSHPOP", "sshpop-key")
	}

	// Get private key from given key file
	var opts []jose.Option
	if passOpt := getProvisionerPasswordOption(ctx); passOpt != nil {
		opts = append(opts, passOpt)
	}
	jwk, err := cryptoutil.LoadJSONWebKey(ctx.String("kms"), sshPOPKeyFile, opts...)
	if err != nil {
		return "", err
	}
	tokenGen := NewTokenGenerator(jwk.KeyID, p.Name,
		fmt.Sprintf("%s#%s", tokAttrs.audience, p.GetIDForToken()), tokAttrs.root,
		tokAttrs.notBefore, tokAttrs.notAfter, jwk)
	switch tokType {
	case SSHRevokeType:
		return tokenGen.Token(tokAttrs.subject, token.WithSSHPOPFile(sshPOPCertFile, jwk.Key))
	case SSHRenewType:
		return tokenGen.Token(tokAttrs.subject, token.WithSSHPOPFile(sshPOPCertFile, jwk.Key))
	case SSHRekeyType:
		return tokenGen.Token(tokAttrs.subject, token.WithSSHPOPFile(sshPOPCertFile, jwk.Key))
	default:
		return "", errors.Errorf("unexpected requested token type for SSHPOP token: %d", tokType)
	}
}

func getProvisionerPasswordOption(ctx *cli.Context) jose.Option {
	switch {
	case ctx.String("provisioner-password-file") != "":
		return jose.WithPasswordFile(ctx.String("provisioner-password-file"))
	case ctx.String("admin-password-file") != "":
		return jose.WithPasswordFile(ctx.String("admin-password-file"))
	case ctx.String("password-file") != "":
		return jose.WithPasswordFile(ctx.String("password-file"))
	default:
		return nil
	}
}

func getProvisionerPasswordPEMOption(ctx *cli.Context) pemutil.Options {
	switch {
	case ctx.String("provisioner-password-file") != "":
		return pemutil.WithPasswordFile(ctx.String("provisioner-password-file"))
	case ctx.String("admin-password-file") != "":
		return pemutil.WithPasswordFile(ctx.String("admin-password-file"))
	case ctx.String("password-file") != "":
		return pemutil.WithPasswordFile(ctx.String("password-file"))
	default:
		return nil
	}
}

// loadJWK loads a JWK based on the following system:
//  1. If a private key is specified on the command line, then load the JWK from
//     that private key.
//  2. No private key was given on the command line. We'll need to use the
//     provided provisioner to load a signing key.
//     a) Offline-mode: load the JWK directly from the provisioner in the CA-config.
//     b) Online-mode: get the provisioner private key from the CA.
func loadJWK(ctx *cli.Context, p *provisioner.JWK, tokAttrs tokenAttrs) (jwk *jose.JSONWebKey, kid string, err error) {
	var opts []jose.Option
	if passOpt := getProvisionerPasswordOption(ctx); passOpt != nil {
		opts = append(opts, passOpt)
	}

	if keyFile := ctx.String("key"); keyFile == "" {
		if p == nil {
			return nil, "", errors.New("no provisioner selected")
		}
		kid = p.Key.KeyID
		// If provisioner is not nil then we must be using the offlineCA.
		var encryptedKey string
		if ctx.IsSet("offline") {
			encryptedKey = p.EncryptedKey
			if encryptedKey == "" {
				return nil, "", errors.Errorf("provisioner '%s' does not have an 'encryptedKey' property", kid)
			}
		} else {
			// Get private key from CA.
			encryptedKey, err = pki.GetProvisionerKey(tokAttrs.caURL, tokAttrs.root, kid)
			if err != nil {
				return nil, "", err
			}
		}

		opts = append(opts, jose.WithPasswordPrompter("Please enter the password to decrypt the provisioner key",
			func(s string) ([]byte, error) {
				return ui.PromptPassword(s)
			}),
		)

		decrypted, err := jose.Decrypt([]byte(encryptedKey), opts...)
		if err != nil {
			return nil, "", err
		}

		jwk = new(jose.JSONWebKey)
		if err := json.Unmarshal(decrypted, jwk); err != nil {
			return nil, "", errors.Wrap(err, "error unmarshaling provisioning key")
		}
	} else {
		jwk, err = cryptoutil.LoadJSONWebKey(ctx.String("kms"), keyFile, opts...)
		if err != nil {
			return nil, "", err
		}

		switch {
		case p != nil:
			kid = p.Key.KeyID
		case tokAttrs.kid != "":
			kid = tokAttrs.kid
		default:
			if kid, err = jose.Thumbprint(jwk); err != nil {
				return nil, "", err
			}
		}
	}
	return
}

func generateJWKToken(ctx *cli.Context, p *provisioner.JWK, tokType int, tokAttrs tokenAttrs) (string, error) {
	jwk, kid, err := loadJWK(ctx, p, tokAttrs)
	if err != nil {
		return "", err
	}

	issuer := tokAttrs.issuer
	if p != nil {
		issuer = p.Name
	}
	// Generate token
	tokenGen := NewTokenGenerator(kid, issuer, tokAttrs.audience, tokAttrs.root,
		tokAttrs.notBefore, tokAttrs.notAfter, jwk)
	switch tokType {
	case SignType:
		return tokenGen.SignToken(tokAttrs.subject, tokAttrs.sans)
	case RevokeType:
		return tokenGen.RevokeToken(tokAttrs.subject)
	case SSHUserSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHUserCert,
			tokAttrs.sans, tokAttrs.certNotBefore, tokAttrs.certNotAfter)
	case SSHHostSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHHostCert,
			tokAttrs.sans, tokAttrs.certNotBefore, tokAttrs.certNotAfter)
	default:
		return tokenGen.Token(tokAttrs.subject)
	}
}

func generateRenewToken(ctx *cli.Context, aud, sub string) (string, error) {
	renewCert := ctx.String("x5c-cert")
	if renewCert == "" {
		return "", errs.RequiredFlag(ctx, "x5c-cert")
	}
	renewKey := ctx.String("x5c-key")
	if renewKey == "" {
		return "", errs.RequiredFlag(ctx, "x5c-key")
	}

	bundle, err := pemutil.ReadCertificateBundle(renewCert)
	if err != nil {
		return "", err
	}
	if len(bundle) == 0 {
		return "", errs.InvalidFlagValueMsg(ctx, "--x5c-cert", renewCert, "certificate not found")
	}
	key, err := pemutil.Read(renewKey)
	if err != nil {
		return "", err
	}
	if sub != "" && sub != bundle[0].Subject.CommonName {
		return "", errors.Errorf("positional argument <subject> must match the certificate common name")
	}
	claims, err := token.NewClaims(
		token.WithAudience(aud),
		token.WithIssuer("step-ca-client/1.0"),
		token.WithSubject(bundle[0].Subject.CommonName),
	)
	if err != nil {
		return "", errors.Wrap(err, "error creating renew token")
	}
	var x5c []string
	for _, crt := range bundle {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(crt.Raw))
	}
	if claims.ExtraHeaders == nil {
		claims.ExtraHeaders = make(map[string]interface{})
	}
	claims.ExtraHeaders[jose.X5cInsecureKey] = x5c

	tok, err := claims.Sign("", key)
	if err != nil {
		return "", errors.Wrap(err, "error creating renew token")
	}
	return tok, nil
}

func getSigningAlgorithm(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported public key type ECDSA %s", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return jose.DefaultRSASigAlgorithm, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", k)
	}
}
