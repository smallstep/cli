package pki

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/authority"
	"github.com/smallstep/ca-component/ca"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/pkg/x509"
	"github.com/smallstep/cli/utils"
	"golang.org/x/crypto/ssh"
)

const (
	// ConfigPath is the directory name under the step path where the configuration
	// files will be stored.
	configPath = "config"
	// PublicPath is the directory name under the step path where the public keys
	// will be stored.
	publicPath = "secrets"
	// PublicPath is the directory name under the step path where the private keys
	// will be stored.
	privatePath = "secrets"
)

const (
	// OTTKeyType is the default type of the one-time token key.
	OTTKeyType = jose.EC
	// OTTKeyCurve is the default curve of the one-time token key.
	OTTKeyCurve = jose.P256
	// OTTKeyAlg is the default algorithm of the one-time token key.
	OTTKeyAlg = jose.ES256
	// OTTKeySize is the default size of the one-time token key.
	OTTKeySize = 0
)

// GetConfigPath returns the directory where the configuration files are stored
// based on the STEPPATH environment variable.
func GetConfigPath() string {
	return filepath.Join(config.StepPath(), configPath)
}

// GetPublicPath returns the directory where the public keys are stored based on
// the STEPPATH environment variable.
func GetPublicPath() string {
	return filepath.Join(config.StepPath(), publicPath)
}

// GetSecretsPath returns the directory where the private keys are stored based
// on the STEPPATH environment variable.
func GetSecretsPath() string {
	return filepath.Join(config.StepPath(), privatePath)
}

// GetRootCAPath returns the path where the root CA is stored based on the
// STEPPATH environment variable.
func GetRootCAPath() string {
	return filepath.Join(config.StepPath(), publicPath, "root_ca.crt")
}

// GetOTTKeyPath returns the path where the ont-time token key is stored based
// on the STEPPATH environment variable.
func GetOTTKeyPath() string {
	return filepath.Join(config.StepPath(), privatePath, "ott_key")
}

// GetProvisioners returns the map of provisioners on the given CA.
func GetProvisioners(caURL, rootFile string) ([]*authority.Provisioner, error) {
	if len(rootFile) == 0 {
		rootFile = GetRootCAPath()
	}
	client, err := ca.NewClient(caURL, ca.WithRootFile(rootFile))
	if err != nil {
		return nil, err
	}
	cursor := ""
	provisioners := []*authority.Provisioner{}
	for {
		resp, err := client.Provisioners(ca.WithProvisionerCursor(cursor), ca.WithProvisionerLimit(100))
		if err != nil {
			return nil, err
		}
		provisioners = append(provisioners, resp.Provisioners...)
		if resp.NextCursor == "" {
			return provisioners, nil
		}
		cursor = resp.NextCursor
	}
}

// GetProvisionerKey returns the encrypted provisioner key with the for the
// given kid.
func GetProvisionerKey(caURL, rootFile, kid string) (string, error) {
	if len(rootFile) == 0 {
		rootFile = GetRootCAPath()
	}
	client, err := ca.NewClient(caURL, ca.WithRootFile(rootFile))
	if err != nil {
		return "", err
	}
	resp, err := client.ProvisionerKey(kid)
	if err != nil {
		return "", err
	}
	return resp.Key, nil
}

// PKI represents the Public Key Infrastructure used by a certificate authority.
type PKI struct {
	root, rootKey                   string
	intermediate, intermediateKey   string
	sshUserKey, sshHostKey          string
	country, locality, organization string
	config                          string
	ottPublicKey                    *jose.JSONWebKey
	ottPrivateKey                   *jose.JSONWebEncryption
	issuer                          string
	address                         string
	dnsNames                        []string
}

// New creates a new PKI configuration.
func New(public, private, config string) (*PKI, error) {
	var err error

	if _, err = os.Stat(public); os.IsNotExist(err) {
		if err = os.MkdirAll(public, 0700); err != nil {
			return nil, errs.FileError(err, public)
		}
	}
	if _, err = os.Stat(private); os.IsNotExist(err) {
		if err = os.MkdirAll(private, 0700); err != nil {
			return nil, errs.FileError(err, private)
		}
	}
	if _, err = os.Stat(config); os.IsNotExist(err) {
		if err = os.MkdirAll(config, 0700); err != nil {
			return nil, errs.FileError(err, config)
		}
	}

	// get absolute path for dir/name
	getPath := func(dir string, name string) (string, error) {
		s, err := filepath.Abs(filepath.Join(dir, name))
		return s, errors.Wrapf(err, "error getting absolute path for %s", name)
	}

	p := &PKI{
		issuer:   "step-cli",
		address:  "127.0.0.1:9000",
		dnsNames: []string{"127.0.0.1"},
	}
	if p.root, err = getPath(public, "root_ca.crt"); err != nil {
		return nil, err
	}
	if p.rootKey, err = getPath(private, "root_ca_key"); err != nil {
		return nil, err
	}
	if p.intermediate, err = getPath(public, "intermediate_ca.crt"); err != nil {
		return nil, err
	}
	if p.intermediateKey, err = getPath(private, "intermediate_ca_key"); err != nil {
		return nil, err
	}
	if p.sshUserKey, err = getPath(private, "ssh_user_key"); err != nil {
		return nil, err
	}
	if p.sshHostKey, err = getPath(private, "ssh_host_key"); err != nil {
		return nil, err
	}
	if p.config, err = getPath(config, "ca.json"); err != nil {
		return nil, err
	}

	return p, nil
}

// SetIssuer sets the issuer of the OTT keys.
func (p *PKI) SetIssuer(s string) {
	p.issuer = s
}

// SetAddress sets the listening address of the CA.
func (p *PKI) SetAddress(s string) {
	p.address = s
}

// SetDNSNames sets the dns names of the CA.
func (p *PKI) SetDNSNames(s []string) {
	p.dnsNames = s
}

// GenerateKeyPairs generates the key pairs used by the certificate authority.
func (p *PKI) GenerateKeyPairs(pass []byte) error {
	var err error
	// Create OTT key pair, the user doesn't need to know about this.
	// Created in default secrets directory because it is required by `new-token`.
	p.ottPublicKey, p.ottPrivateKey, err = generateOTTKeyPair(pass)
	if err != nil {
		return err
	}

	// Create ssh user certificate signing key pair, the user doesn't need to know about this.
	if err := generateCASigningKeyPair(p.sshUserKey, pass); err != nil {
		return err
	}

	// Create ssh host certificate signing key pair, the user doesn't need to know about this.
	if err := generateCASigningKeyPair(p.sshHostKey, pass); err != nil {
		return err
	}

	return nil
}

// GenerateRootCertificate generates a root certificate with the given name.
func (p *PKI) GenerateRootCertificate(name string, pass []byte) (*x509.Certificate, interface{}, error) {
	rootProfile, err := x509util.NewRootProfile(name)
	if err != nil {
		return nil, nil, err
	}

	rootBytes, err := rootProfile.CreateWriteCertificate(p.root, p.rootKey, string(pass))
	if err != nil {
		return nil, nil, err
	}

	rootCrt, err := x509.ParseCertificate(rootBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing root certificate")
	}

	return rootCrt, rootProfile.SubjectPrivateKey(), nil
}

// WriteRootCertificate writes to disk the given certificate and key.
func (p *PKI) WriteRootCertificate(rootCrt *x509.Certificate, rootKey interface{}, pass []byte) error {
	if err := utils.WriteFile(p.root, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCrt.Raw,
	}), 0600); err != nil {
		return err
	}

	_, err := pemutil.Serialize(rootKey, pemutil.WithEncryption([]byte(pass)), pemutil.ToFile(p.rootKey, 0600))
	if err != nil {
		return err
	}
	return nil
}

// GenerateIntermediateCertificate generates an intermediate certificate with
// the given name.
func (p *PKI) GenerateIntermediateCertificate(name string, rootCrt *x509.Certificate, rootKey interface{}, pass []byte) error {
	interProfile, err := x509util.NewIntermediateProfile(name, rootCrt, rootKey)
	if err != nil {
		return err
	}
	_, err = interProfile.CreateWriteCertificate(p.intermediate, p.intermediateKey, string(pass))
	return err
}

// Save stores the pki on a json file that will be used as the certificate
// authority configuration.
func (p *PKI) Save() error {
	fmt.Println()
	fmt.Printf("Root certificate: %s\n", p.root)
	fmt.Printf("Root private key: %s\n", p.rootKey)
	fmt.Printf("Intermediate certificate: %s\n", p.intermediate)
	fmt.Printf("Intermediate private key: %s\n", p.intermediateKey)

	key, err := p.ottPrivateKey.CompactSerialize()
	if err != nil {
		return errors.Wrap(err, "error serializing private key")
	}

	config := authority.Config{
		Root:             p.root,
		IntermediateCert: p.intermediate,
		IntermediateKey:  p.intermediateKey,
		Address:          p.address,
		DNSNames:         p.dnsNames,
		Logger:           []byte(`{"format": "text"}`),
		AuthorityConfig: &authority.AuthConfig{
			DisableIssuedAtCheck: false,
			Provisioners: []*authority.Provisioner{
				{Issuer: p.issuer, Type: "jwk", Key: p.ottPublicKey, EncryptedKey: key},
			},
		},
		TLS: &tlsutil.TLSOptions{
			MinVersion:    x509util.DefaultTLSMinVersion,
			MaxVersion:    x509util.DefaultTLSMaxVersion,
			Renegotiation: x509util.DefaultTLSRenegotiation,
			CipherSuites:  x509util.DefaultTLSCipherSuites,
		},
	}

	b, err := json.MarshalIndent(config, "", "   ")
	if err != nil {
		return errors.Wrapf(err, "error marshalling %s", p.config)
	}

	if err = ioutil.WriteFile(p.config, b, 0666); err != nil {
		return errs.FileError(err, p.config)
	}

	fmt.Println()
	fmt.Printf("Certificate Authority configuration: %s\n", p.config)

	fmt.Println()
	fmt.Println("Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.")

	return nil
}

// generateOTTKeyPair generates a keypair using the default crypto algorithms.
// This key pair will be used to sign/verify one-time-tokens.
func generateOTTKeyPair(pass []byte) (*jose.JSONWebKey, *jose.JSONWebEncryption, error) {
	if len(pass) == 0 {
		return nil, nil, errors.New("password cannot be empty when initializing simple pki")
	}

	// Generate the OTT key
	jwk, err := jose.GenerateJWK(OTTKeyType, OTTKeyCurve, OTTKeyAlg, "sig", "", OTTKeySize)
	if err != nil {
		return nil, nil, err
	}

	// The thumbprint is computed from the public key
	hash, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating JWK thumbprint")
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(hash)

	b, err := json.Marshal(jwk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error marshaling JWK")
	}

	// Encrypt private key using PBES2
	salt, err := randutil.Salt(jose.PBKDF2SaltSize)
	if err != nil {
		return nil, nil, err
	}
	recipient := jose.Recipient{
		Algorithm:  jose.PBES2_HS256_A128KW,
		Key:        pass,
		PBES2Count: jose.PBKDF2Iterations,
		PBES2Salt:  salt,
	}

	opts := new(jose.EncrypterOptions)
	opts.WithContentType(jose.ContentType("jwk+json"))

	encrypter, err := jose.NewEncrypter(jose.DefaultEncAlgorithm, recipient, opts)
	if err != nil {
		return nil, nil, errs.Wrap(err, "error creating cipher")
	}

	jwe, err := encrypter.Encrypt(b)
	if err != nil {
		return nil, nil, errs.Wrap(err, "error encrypting data")
	}

	public := jwk.Public()
	return &public, jwe, nil
}

// generateCASigningKeyPair generates a certificate signing public/private key
// pair for signing ssh certificates.
func generateCASigningKeyPair(keyFile string, pass []byte) error {
	if len(pass) == 0 {
		return errors.New("password cannot be empty when initializing simple pki")
	}

	pubFile := keyFile + ".pub"

	pub, priv, err := keys.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return errors.Wrap(err, "error creating SSH public key")
	}

	err = ioutil.WriteFile(pubFile, ssh.MarshalAuthorizedKey(sshPub), os.FileMode(0644))
	if err != nil {
		return errs.FileError(err, pubFile)
	}

	_, err = pemutil.Serialize(priv, pemutil.WithEncryption([]byte(pass)), pemutil.ToFile(keyFile, 0644))
	return err
}
