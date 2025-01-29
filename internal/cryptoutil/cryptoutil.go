package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/smallstep/cli/internal/plugin"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// IsKMS returns true if the given uri is a KMS URI.
func IsKMS(rawuri string) bool {
	typ, err := kms.TypeOf(rawuri)
	if err != nil || typ == apiv1.DefaultKMS {
		return false
	}
	return true
}

// Attestor is the interface implemented by step-kms-plugin using the key, sign,
// and attest commands.
type Attestor interface {
	crypto.Signer
	Attest() ([]byte, error)
}

func PublicKey(kmsURI, name string, opts ...pemutil.Options) (crypto.PublicKey, error) {
	if kmsURI == "" {
		s, err := pemutil.Read(name, opts...)
		if err != nil {
			return nil, err
		}
		if pub, ok := s.(crypto.PublicKey); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("file %s does not contain a valid public key", name)
	}

	k, err := newKMSPublicKey(kmsURI, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return k.Public(), nil
}

// CreateSigner reads a key from a file with a given name or creates a signer
// with the given kms and name uri.
func CreateSigner(kmsURI, name string, opts ...pemutil.Options) (crypto.Signer, error) {
	if kmsURI == "" || isSoftKMS(kmsURI) {
		s, err := pemutil.Read(name, opts...)
		if err != nil {
			return nil, err
		}
		if sig, ok := s.(crypto.Signer); ok {
			return sig, nil
		}
		return nil, fmt.Errorf("file %s does not contain a valid private key", name)
	}

	return newKMSSigner(kmsURI, name)
}

func isSoftKMS(kmsURI string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(kmsURI)), "softkms")
}

// LoadCertificate returns a x509.Certificate from a kms or file
func LoadCertificate(kmsURI, certPath string) ([]*x509.Certificate, error) {
	if kmsURI == "" {
		s, err := pemutil.ReadCertificateBundle(certPath)
		if err != nil {
			return nil, fmt.Errorf("file %s does not contain a valid certificate: %w", certPath, err)
		}
		return s, nil
	}

	name, err := plugin.LookPath("kms")
	if err != nil {
		return nil, err
	}

	args := []string{"certificate"}
	if kmsURI != "" {
		args = append(args, "--kms", kmsURI)
	}
	args = append(args, certPath)

	// Get public key
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}

	cert, err := pemutil.ParseCertificateBundle(out)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// LoadJSONWebKey returns a jose.JSONWebKey from a KMS or a file.
func LoadJSONWebKey(kmsURI, name string, opts ...jose.Option) (*jose.JSONWebKey, error) {
	if kmsURI == "" {
		return jose.ReadKey(name, opts...)
	}

	signer, err := newKMSSigner(kmsURI, name)
	if err != nil {
		return nil, err
	}

	jwk := &jose.JSONWebKey{
		Key: jose.NewOpaqueSigner(signer),
		Use: "sig",
	}

	// Get default signing algorithm for each key type:
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			jwk.Algorithm = jose.ES256
		case elliptic.P384():
			jwk.Algorithm = jose.ES384
		case elliptic.P521():
			jwk.Algorithm = jose.ES512
		default:
			return nil, fmt.Errorf("unsupported elliptic curve %q", pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		jwk.Algorithm = jose.RS256
	case ed25519.PublicKey:
		jwk.Algorithm = jose.EdDSA
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}

	kid, err := jose.Thumbprint(jwk)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = kid

	return jwk, nil
}

// CreateAttestor creates an attestor that will use `step-kms-plugin` with the
// given kms and name.
func CreateAttestor(kmsURI, name string) (Attestor, error) {
	return newKMSSigner(kmsURI, name)
}

// IsKMSSigner returns true if the given signer uses the step-kms-plugin signer.
func IsKMSSigner(signer crypto.Signer) (ok bool) {
	_, ok = signer.(*kmsSigner)
	return
}

// IsX509Signer returns true if the given signer is supported by Go's
// crypto/x509 package to sign X509 certificates. This methods returns true
// for ECDSA, RSA and Ed25519 keys, but if the kms is `sshagentkms:` it will
// only return true for Ed25519 keys.
// TODO(hs): introspect the KMS key to verify that it can actually be
// used for signing? E.g. for Google Cloud KMS RSA keys can be used for
// signing or decryption, but only one of those at a time. Trying to use
// a signing key to decrypt data will result in an error from Cloud KMS.
func IsX509Signer(signer crypto.Signer) bool {
	pub := signer.Public()
	if ks, ok := signer.(*kmsSigner); ok {
		if strings.HasPrefix(strings.ToLower(ks.kms), "sshagentkms:") {
			_, ok = pub.(ed25519.PublicKey)
			return ok
		}
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

type kmsSigner struct {
	crypto.PublicKey
	name     string
	kms, key string
}

type kmsPublicKey struct {
	crypto.PublicKey
	name     string
	kms, key string
}

// exitError returns the error displayed on stderr after running the given
// command.
func exitError(cmd *exec.Cmd, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("command %q failed with:\n%s", cmd.String(), ee.Stderr)
	}
	return fmt.Errorf("command %q failed with: %w", cmd.String(), err)
}

// newKMSSigner creates a signer using `step-kms-plugin` as the signer.
func newKMSSigner(kmsURI, key string) (*kmsSigner, error) {
	name, err := plugin.LookPath("kms")
	if err != nil {
		return nil, err
	}

	args := []string{"key"}
	if kmsURI != "" {
		args = append(args, "--kms", kmsURI)
	}
	args = append(args, key)

	// Get public key
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}

	pub, err := pemutil.Parse(out)
	if err != nil {
		return nil, err
	}

	return &kmsSigner{
		PublicKey: pub,
		name:      name,
		kms:       kmsURI,
		key:       key,
	}, nil
}

// newKMSPublicKey creates a signer using `step-kms-plugin` as the signer.
func newKMSPublicKey(kmsURI, key string) (*kmsPublicKey, error) {
	name, err := plugin.LookPath("kms")
	if err != nil {
		return nil, err
	}

	args := []string{"key"}
	if kmsURI != "" {
		args = append(args, "--kms", kmsURI)
	}
	args = append(args, key)

	// Get public key
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}

	pub, err := pemutil.Parse(out)
	if err != nil {
		return nil, err
	}

	return &kmsPublicKey{
		PublicKey: pub,
		name:      name,
		kms:       kmsURI,
		key:       key,
	}, nil
}

// Public returns the KMS public key
func (s *kmsPublicKey) Public() crypto.PublicKey {
	return s.PublicKey
}

// Public implements crypto.Signer and returns the public key.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign implements crypto.Signer using the `step-kms-plugin`.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	args := []string{"sign", "--format", "base64"}
	if s.kms != "" {
		args = append(args, "--kms", s.kms)
	}
	if _, ok := s.PublicKey.(*rsa.PublicKey); ok {
		if o, pss := opts.(*rsa.PSSOptions); pss {
			// The --salt-length argument requires step-kms-plugin v0.12.0
			args = append(args, "--pss", "--salt-length", strconv.Itoa(o.SaltLength))
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			args = append(args, "--alg", "SHA256")
		case crypto.SHA384:
			args = append(args, "--alg", "SHA384")
		case crypto.SHA512:
			args = append(args, "--alg", "SHA512")
		default:
			return nil, fmt.Errorf("unsupported hash function %q", opts.HashFunc().String())
		}
	}
	args = append(args, s.key)

	//nolint:gosec // arguments controlled by step.
	cmd := exec.Command(s.name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		stdin.Write(digest)
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}
	return base64.StdEncoding.DecodeString(string(out))
}

// Attest returns an attestation certificate using the `step-kms-plugin attest`
// command.
func (s *kmsSigner) Attest() ([]byte, error) {
	args := []string{"attest"}
	if s.kms != "" {
		args = append(args, "--kms", s.kms)
	}
	args = append(args, s.key)

	//nolint:gosec // arguments controlled by step.
	cmd := exec.Command(s.name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}
	return out, nil
}
