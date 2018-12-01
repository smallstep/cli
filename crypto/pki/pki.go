package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	stepX509 "github.com/smallstep/cli/pkg/x509"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
)

const (
	// ConfigPath is the directory name under the step path where the configuration
	// files will be stored.
	configPath = "config"
	// PublicPath is the directory name under the step path where the public keys
	// will be stored.
	publicPath = "certs"
	// PublicPath is the directory name under the step path where the private keys
	// will be stored.
	privatePath = "secrets"
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
	root, rootKey, rootFingerprint  string
	intermediate, intermediateKey   string
	country, locality, organization string
	config, defaults                string
	ottPublicKey                    *jose.JSONWebKey
	ottPrivateKey                   *jose.JSONWebEncryption
	provisioner                     string
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
	if len(config) > 0 {
		if _, err = os.Stat(config); os.IsNotExist(err) {
			if err = os.MkdirAll(config, 0700); err != nil {
				return nil, errs.FileError(err, config)
			}
		}
	}

	// get absolute path for dir/name
	getPath := func(dir string, name string) (string, error) {
		s, err := filepath.Abs(filepath.Join(dir, name))
		return s, errors.Wrapf(err, "error getting absolute path for %s", name)
	}

	p := &PKI{
		provisioner: "step-cli",
		address:     "127.0.0.1:9000",
		dnsNames:    []string{"127.0.0.1"},
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
	if len(config) > 0 {
		if p.config, err = getPath(config, "ca.json"); err != nil {
			return nil, err
		}
		if p.defaults, err = getPath(config, "defaults.json"); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// SetProvisioner sets the provisioner name of the OTT keys.
func (p *PKI) SetProvisioner(s string) {
	p.provisioner = s
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
	p.ottPublicKey, p.ottPrivateKey, err = jose.GenerateDefaultKeyPair(pass)
	if err != nil {
		return err
	}

	return nil
}

// GenerateRootCertificate generates a root certificate with the given name.
func (p *PKI) GenerateRootCertificate(name string, pass []byte) (*stepX509.Certificate, interface{}, error) {
	rootProfile, err := x509util.NewRootProfile(name)
	if err != nil {
		return nil, nil, err
	}

	rootBytes, err := rootProfile.CreateWriteCertificate(p.root, p.rootKey, string(pass))
	if err != nil {
		return nil, nil, err
	}

	rootCrt, err := stepX509.ParseCertificate(rootBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing root certificate")
	}

	sum := sha256.Sum256(rootCrt.Raw)
	p.rootFingerprint = strings.ToLower(hex.EncodeToString(sum[:]))

	return rootCrt, rootProfile.SubjectPrivateKey(), nil
}

// WriteRootCertificate writes to disk the given certificate and key.
func (p *PKI) WriteRootCertificate(rootCrt *stepX509.Certificate, rootKey interface{}, pass []byte) error {
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
func (p *PKI) GenerateIntermediateCertificate(name string, rootCrt *stepX509.Certificate, rootKey interface{}, pass []byte) error {
	interProfile, err := x509util.NewIntermediateProfile(name, rootCrt, rootKey)
	if err != nil {
		return err
	}
	_, err = interProfile.CreateWriteCertificate(p.intermediate, p.intermediateKey, string(pass))
	return err
}

// TellPKI outputs the locations of public and private keys generated
// generated for a new PKI. Generally this will consist of a root certificate
// and key and an intermediate certificate and key.
func (p *PKI) TellPKI() {
	ui.Println()
	ui.PrintSelected("Root certificate", p.root)
	ui.PrintSelected("Root private key", p.rootKey)
	ui.PrintSelected("Root fingerprint", p.rootFingerprint)
	ui.PrintSelected("Intermediate certificate", p.intermediate)
	ui.PrintSelected("Intermediate private key", p.intermediateKey)
}

type caDefaults struct {
	CAUrl       string `json:"ca-url"`
	CAConfig    string `json:"ca-config"`
	Fingerprint string `json:"fingerprint"`
	Root        string `json:"root"`
}

// Save stores the pki on a json file that will be used as the certificate
// authority configuration.
func (p *PKI) Save() error {
	p.TellPKI()

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
				{Name: p.provisioner, Type: "jwk", Key: p.ottPublicKey, EncryptedKey: key},
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
	if err = utils.WriteFile(p.config, b, 0666); err != nil {
		return errs.FileError(err, p.config)
	}

	// Generate the CA URL.
	url := p.dnsNames[0]
	_, port, err := net.SplitHostPort(p.address)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", p.address)
	}
	if port == "443" {
		url = fmt.Sprintf("https://%s", url)
	} else {
		url = fmt.Sprintf("https://%s:%s", url, port)
	}

	defaults := &caDefaults{
		Root:        p.root,
		CAConfig:    p.config,
		CAUrl:       url,
		Fingerprint: p.rootFingerprint,
	}
	b, err = json.MarshalIndent(defaults, "", "   ")
	if err != nil {
		return errors.Wrapf(err, "error marshalling %s", p.defaults)
	}
	if err = utils.WriteFile(p.defaults, b, 0666); err != nil {
		return errs.FileError(err, p.defaults)
	}

	ui.PrintSelected("Default configuration", p.defaults)
	ui.PrintSelected("Certificate Authority configuration", p.config)
	ui.Println()
	ui.Println("Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.")

	return nil
}
