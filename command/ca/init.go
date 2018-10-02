package ca

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func initCommand() cli.Command {
	return cli.Command{
		Name:      "init",
		Action:    cli.ActionFunc(initAction),
		Usage:     "initializes the CA PKI",
		UsageText: `**step ca init**`,
		Description: `**step ca init** command initializes a public key infrastructure (PKI) to be
 used by the Certificate Authority`,
	}
}

func initAction(ctx *cli.Context) error {
	if err := assertCryptoRand(); err != nil {
		return err
	}

	stepPath := config.StepPath()
	defaultSecrets := stepPath + "/secrets"
	defaultConfig := stepPath + "/config"

	fmt.Fprintf(os.Stderr, "What would you like to name your new PKI? (e.g. Smallstep): ")
	name, err := utils.ReadString(os.Stdin)
	if err != nil {
		return err
	}

	pass, err := utils.ReadPasswordGenerate("What do you want your password to be? [leave empty and we'll generate one]: ")
	if err != nil {
		return err
	}

	p, err := newPKI(defaultSecrets, defaultSecrets, defaultConfig)
	if err != nil {
		return err
	}

	// Generate ott and ssh key pairs
	if err := p.GenerateKeyPairs(pass); err != nil {
		return err
	}

	fmt.Println()
	fmt.Print("Generating root certificate... \n")

	rootCrt, rootKey, err := p.GenerateRootCertificate(name+" Root CA", pass)
	if err != nil {
		return err
	}

	fmt.Println("all done!")

	fmt.Println()
	fmt.Print("Generating intermediate certificate... \n")

	err = p.GenerateIntermediateCertificate(name+" Intermediate CA", rootCrt, rootKey, pass)
	if err != nil {
		return err
	}

	fmt.Println("all done!")

	if err = p.Save(); err != nil {
		return err
	}

	return nil
}

// assertCrytoRand asserts that a cryptographically secure random number
// generator is available, it will return an error otherwise.
func assertCryptoRand() error {
	buf := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return errs.NewError("crypto/rand is unavailable: Read() failed with %#v", err)
	}
	return nil
}

// type pki struct {
// 	root, rootKey                   string
// 	intermediate, intermediateKey   string
// 	ottPublicKey, ottPrivateKey     string
// 	sshUserKey, sshHostKey          string
// 	country, locality, organization string
// 	config                          string
// }

// func validatePaths(public, private, config string) (*pki, error) {
// 	var err error

// 	if _, err = os.Stat(public); os.IsNotExist(err) {
// 		if err = os.MkdirAll(public, 0700); err != nil {
// 			return nil, errs.FileError(err, public)
// 		}
// 	}
// 	if _, err = os.Stat(private); os.IsNotExist(err) {
// 		if err = os.MkdirAll(private, 0700); err != nil {
// 			return nil, errs.FileError(err, private)
// 		}
// 	}
// 	if _, err = os.Stat(config); os.IsNotExist(err) {
// 		if err = os.MkdirAll(config, 0700); err != nil {
// 			return nil, errs.FileError(err, config)
// 		}
// 	}

// 	// get absolute path for dir/name
// 	getPath := func(dir string, name string) (string, error) {
// 		s, err := filepath.Abs(filepath.Join(dir, name))
// 		return s, errors.Wrapf(err, "error getting absolute path for %s", name)
// 	}

// 	p := new(pki)
// 	if p.root, err = getPath(public, "root_ca.crt"); err != nil {
// 		return nil, err
// 	}
// 	if p.rootKey, err = getPath(private, "root_ca_key"); err != nil {
// 		return nil, err
// 	}
// 	if p.intermediate, err = getPath(public, "intermediate_ca.crt"); err != nil {
// 		return nil, err
// 	}
// 	if p.intermediateKey, err = getPath(private, "intermediate_ca_key"); err != nil {
// 		return nil, err
// 	}
// 	if p.ottPublicKey, err = getPath(public, "ott_key.public"); err != nil {
// 		return nil, err
// 	}
// 	if p.ottPrivateKey, err = getPath(private, "ott_key"); err != nil {
// 		return nil, err
// 	}
// 	if p.sshUserKey, err = getPath(private, "ssh_user_key"); err != nil {
// 		return nil, err
// 	}
// 	if p.sshHostKey, err = getPath(private, "ssh_host_key"); err != nil {
// 		return nil, err
// 	}
// 	if p.config, err = getPath(config, "ca.step"); err != nil {
// 		return nil, err
// 	}

// 	return p, nil
// }

// // generateOTTKeyPair generates a keypair using the default crypto algorithms.
// // This key pair will be used to sign/verify one-time-tokens.
// func generateOTTKeyPair(ottPublicKey, ottPrivateKey string, pass []byte) error {
// 	if len(pass) == 0 {
// 		return errors.New("password cannot be empty when initializing simple pki")
// 	}

// 	pub, priv, err := keys.GenerateDefaultKeyPair()
// 	if err != nil {
// 		return err
// 	}

// 	if _, err := pemutil.Serialize(pub, pemutil.ToFile(ottPublicKey, 0644)); err != nil {
// 		return err
// 	}

// 	_, err = pemutil.Serialize(priv, pemutil.WithEncryption(pass), pemutil.ToFile(ottPrivateKey, 0644))
// 	return err
// }

// // generateCASigningKeyPair generates a certificate signing public/private key
// // pair for signing ssh certificates.
// func generateCASigningKeyPair(keyFile string, pass []byte) error {
// 	if len(pass) == 0 {
// 		return errors.New("password cannot be empty when initializing simple pki")
// 	}

// 	pubFile := keyFile + ".pub"

// 	pub, priv, err := keys.GenerateDefaultKeyPair()
// 	if err != nil {
// 		return err
// 	}

// 	sshPub, err := ssh.NewPublicKey(pub)
// 	if err != nil {
// 		return errors.Wrap(err, "error creating SSH public key")
// 	}

// 	err = ioutil.WriteFile(pubFile, ssh.MarshalAuthorizedKey(sshPub), os.FileMode(0644))
// 	if err != nil {
// 		return errs.FileError(err, pubFile)
// 	}

// 	_, err = pemutil.Serialize(priv, pemutil.WithEncryption([]byte(pass)), pemutil.ToFile(keyFile, 0644))
// 	return err
// }

// func savePKI(p *pki) error {
// 	fmt.Println()
// 	fmt.Printf("Root certificate: %s\n", p.root)
// 	fmt.Printf("Root private key: %s\n", p.rootKey)
// 	fmt.Printf("Intermediate certificate: %s\n", p.intermediate)
// 	fmt.Printf("Intermediate private key: %s\n", p.intermediateKey)

// 	config := map[string]interface{}{
// 		"root":     p.root,
// 		"crt":      p.intermediate,
// 		"key":      p.intermediateKey,
// 		"address":  "127.0.0.1:9000",
// 		"dnsNames": []string{"127.0.0.1"},
// 		"logger":   map[string]interface{}{"format": "text"},
// 		"tls": map[string]interface{}{
// 			"minVersion":    x509util.DefaultTLSMinVersion,
// 			"maxVersion":    x509util.DefaultTLSMaxVersion,
// 			"renegotiation": x509util.DefaultTLSRenegotiation,
// 			"cipherSuites":  x509util.DefaultTLSCipherSuites,
// 		},
// 		"authority": map[string]interface{}{
// 			"type": "jwt",
// 			"key":  p.ottPublicKey,
// 			"template": map[string]interface{}{
// 				"country":      p.country,
// 				"locality":     p.locality,
// 				"organization": p.organization,
// 			},
// 		},
// 	}

// 	b, err := json.MarshalIndent(config, "", "   ")
// 	if err != nil {
// 		return errors.Wrapf(err, "error marshalling %s", p.config)
// 	}

// 	if err = ioutil.WriteFile(p.config, b, 0666); err != nil {
// 		return errs.FileError(err, p.config)
// 	}

// 	fmt.Println()
// 	fmt.Printf("Certificate Authority configuration: %s\n", p.config)

// 	fmt.Println()
// 	fmt.Println("Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.")

// 	return nil
// }
