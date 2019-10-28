package cautils

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/token/provision"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
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
	if len(t.root) > 0 {
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
	return t.Token(sub, opts...)
}

// RevokeToken generates a X.509 certificate revoke token.
func (t *TokenGenerator) RevokeToken(sub string, opts ...token.Options) (string, error) {
	return t.Token(sub, opts...)
}

// SignSSHToken generates a SSH certificate signing token.
func (t *TokenGenerator) SignSSHToken(sub, certType string, principals []string, notBefore, notAfter provisioner.TimeDuration, opts ...token.Options) (string, error) {
	opts = append([]token.Options{token.WithSSH(provisioner.SSHOptions{
		CertType:    certType,
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
	if ctx.Bool("console") {
		args = append(args, "--console")
	}
	if p.ListenAddress != "" {
		args = append(args, "--listen", p.ListenAddress)
	}
	out, err := exec.Step(args...)
	if err != nil {
		return "", err
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

func generateK8sSAToken(ctx *cli.Context, p *provisioner.K8sSA) (string, error) {
	path := ctx.String("k8ssa-token-path")
	if len(path) == 0 {
		path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	tokBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(err, "error reading kubernetes service account token")
	}
	return string(tokBytes), nil
}

func generateX5CToken(ctx *cli.Context, p *provisioner.X5C, tokType int, tokAttrs tokenAttrs) (string, error) {
	x5cCertFile := ctx.String("x5c-cert")
	x5cKeyFile := ctx.String("x5c-key")
	if len(x5cCertFile) == 0 {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "X5C", "x5c-cert")
	}
	if len(x5cKeyFile) == 0 {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "X5C", "x5c-key")
	}

	// Get private key from given key file
	var opts []jose.Option
	if passwordFile := ctx.String("password-file"); len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}
	jwk, err := jose.ParseKey(x5cKeyFile, opts...)
	if err != nil {
		return "", err
	}
	tokenGen := NewTokenGenerator(jwk.KeyID, p.Name,
		fmt.Sprintf("%s#%s", tokAttrs.audience, p.GetID()), tokAttrs.root,
		tokAttrs.notBefore, tokAttrs.notAfter, jwk)
	switch tokType {
	case SignType:
		return tokenGen.SignToken(tokAttrs.subject, tokAttrs.sans, token.WithX5CFile(x5cCertFile, jwk.Key))
	case RevokeType:
		return tokenGen.RevokeToken(tokAttrs.subject, token.WithX5CFile(x5cCertFile, jwk.Key))
	case SSHUserSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHUserCert, tokAttrs.sans,
			tokAttrs.certNotBefore, tokAttrs.certNotAfter, token.WithX5CFile(x5cCertFile, jwk.Key))
	case SSHHostSignType:
		return tokenGen.SignSSHToken(tokAttrs.subject, provisioner.SSHHostCert, tokAttrs.sans,
			tokAttrs.certNotBefore, tokAttrs.certNotAfter, token.WithX5CFile(x5cCertFile, jwk.Key))
	default:
		return tokenGen.Token(tokAttrs.subject, token.WithX5CFile(x5cCertFile, jwk.Key))
	}
}

func generateSSHPOPToken(ctx *cli.Context, p *provisioner.SSHPOP, tokType int, tokAttrs tokenAttrs) (string, error) {
	sshPOPCertFile := ctx.String("sshpop-cert")
	sshPOPKeyFile := ctx.String("sshpop-key")
	if len(sshPOPCertFile) == 0 {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "SSHPOP", "sshpop-cert")
	}
	if len(sshPOPKeyFile) == 0 {
		return "", errs.RequiredWithProvisionerTypeFlag(ctx, "SSHPOP", "sshpop-key")
	}

	// Get private key from given key file
	var opts []jose.Option
	if passwordFile := ctx.String("password-file"); len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}
	jwk, err := jose.ParseKey(sshPOPKeyFile, opts...)
	if err != nil {
		return "", err
	}
	tokenGen := NewTokenGenerator(jwk.KeyID, p.Name,
		fmt.Sprintf("%s#%s", tokAttrs.audience, p.GetID()), tokAttrs.root,
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

// loadJWK loads a JWK based on the following system:
//  1. If a private key is specified on the command line, then load the JWK from
//     that private key.
//  2. No private key was given on the command line. We'll need to use the
//     provided provisioner to load a signing key.
//    a) Offline-mode: load the JWK directly from the provisioner in the CA-config.
//    b) Online-mode: get the provisioner private key from the CA.
func loadJWK(ctx *cli.Context, p *provisioner.JWK, tokAttrs tokenAttrs) (jwk *jose.JSONWebKey, kid string, err error) {
	var opts []jose.Option
	if passwordFile := ctx.String("password-file"); len(passwordFile) != 0 {
		opts = append(opts, jose.WithPasswordFile(passwordFile))
	}

	if keyFile := ctx.String("key"); len(keyFile) == 0 {
		if p == nil {
			return nil, "", errors.New("no provisioner selected")
		}
		kid = p.Key.KeyID
		// If provisioner is not nil then we must be using the offlineCA.
		var encryptedKey string
		if ctx.IsSet("offline") {
			encryptedKey = p.EncryptedKey
			if len(encryptedKey) == 0 {
				return nil, "", errors.Errorf("provisioner '%s' does not have an 'encryptedKey' property", kid)
			}
		} else {
			// Get private key from CA.
			encryptedKey, err = pki.GetProvisionerKey(tokAttrs.caURL, tokAttrs.root, kid)
			if err != nil {
				return nil, "", err
			}
		}

		// Add template with check mark
		opts = append(opts, jose.WithUIOptions(
			ui.WithPromptTemplates(ui.PromptTemplates()),
		))

		decrypted, err := jose.Decrypt("Please enter the password to decrypt the provisioner key", []byte(encryptedKey), opts...)
		if err != nil {
			return nil, "", err
		}

		jwk = new(jose.JSONWebKey)
		if err := json.Unmarshal(decrypted, jwk); err != nil {
			return nil, "", errors.Wrap(err, "error unmarshalling provisioning key")
		}
	} else {
		// Get private key from given key file
		jwk, err = jose.ParseKey(keyFile, opts...)
		if err != nil {
			return nil, "", err
		}

		if p != nil {
			kid = p.Key.KeyID
		} else if len(tokAttrs.kid) > 0 {
			kid = tokAttrs.kid
		} else {
			hash, err := jwk.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, "", errors.Wrap(err, "error generating JWK thumbprint")
			}
			kid = base64.RawURLEncoding.EncodeToString(hash)
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
