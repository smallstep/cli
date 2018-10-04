package pki

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/pkg/x509"
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

// PKI represents the Public Key Infrastructure used by a certificate authority.
type PKI struct {
	root, rootKey                   string
	intermediate, intermediateKey   string
	ottPublicKey, ottPrivateKey     string
	sshUserKey, sshHostKey          string
	country, locality, organization string
	config                          string
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

	p := new(PKI)
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
	if p.ottPublicKey, err = getPath(public, "ott_key.public"); err != nil {
		return nil, err
	}
	if p.ottPrivateKey, err = getPath(private, "ott_key"); err != nil {
		return nil, err
	}
	if p.sshUserKey, err = getPath(private, "ssh_user_key"); err != nil {
		return nil, err
	}
	if p.sshHostKey, err = getPath(private, "ssh_host_key"); err != nil {
		return nil, err
	}
	if p.config, err = getPath(config, "ca.step"); err != nil {
		return nil, err
	}

	return p, nil
}

// GenerateKeyPairs generates the key pairs used by the certificate authority.
func (p *PKI) GenerateKeyPairs(pass []byte) error {
	// Create OTT key pair, the user doesn't need to know about this.
	// Created in default secrets directory because it is required by `new-token`.
	if err := generateOTTKeyPair(p.ottPublicKey, p.ottPrivateKey, pass); err != nil {
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

	config := map[string]interface{}{
		"root":     p.root,
		"crt":      p.intermediate,
		"key":      p.intermediateKey,
		"address":  "127.0.0.1:9000",
		"dnsNames": []string{"127.0.0.1"},
		"logger":   map[string]interface{}{"format": "text"},
		"tls": map[string]interface{}{
			"minVersion":    x509util.DefaultTLSMinVersion,
			"maxVersion":    x509util.DefaultTLSMaxVersion,
			"renegotiation": x509util.DefaultTLSRenegotiation,
			"cipherSuites":  x509util.DefaultTLSCipherSuites,
		},
		"authority": map[string]interface{}{
			"type": "jwt",
			"key":  p.ottPublicKey,
			"template": map[string]interface{}{
				"country":      p.country,
				"locality":     p.locality,
				"organization": p.organization,
			},
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
func generateOTTKeyPair(ottPublicKey, ottPrivateKey string, pass []byte) error {
	if len(pass) == 0 {
		return errors.New("password cannot be empty when initializing simple pki")
	}

	pub, priv, err := keys.GenerateDefaultKeyPair()
	if err != nil {
		return err
	}

	if _, err := pemutil.Serialize(pub, pemutil.ToFile(ottPublicKey, 0644)); err != nil {
		return err
	}

	_, err = pemutil.Serialize(priv, pemutil.WithEncryption(pass), pemutil.ToFile(ottPrivateKey, 0644))
	return err
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
