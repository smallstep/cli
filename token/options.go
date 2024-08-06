package token

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	nebula "github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x25519"
)

// Options is a function that set claims.
type Options func(c *Claims) error

// WithClaim is an Options function that adds a custom claim to the JWT.
func WithClaim(name string, value interface{}) Options {
	return func(c *Claims) error {
		if name == "" {
			return errors.New("name cannot be empty")
		}
		c.Set(name, value)
		return nil
	}
}

// WithRootCA returns an Options function that calculates the SHA256 of the
// given root certificate to be used in the token claims. If this method it's
// not used the default root certificate in the $STEPPATH secrets directory will
// be used.
func WithRootCA(path string) Options {
	return func(c *Claims) error {
		cert, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(cert.Raw)
		c.Set(RootSHAClaim, hex.EncodeToString(sum[:]))
		return nil
	}
}

// WithSHA returns an Options function that sets the SHA claim to the given
// value.
func WithSHA(sum string) Options {
	return func(c *Claims) error {
		c.Set(RootSHAClaim, sum)
		return nil
	}
}

// WithSANS returns an Options function that sets the list of required SANs
// in the token claims.
func WithSANS(sans []string) Options {
	return func(c *Claims) error {
		c.Set(SANSClaim, sans)
		return nil
	}
}

// WithStep returns an Options function that sets the step claim in the payload.
func WithStep(v interface{}) Options {
	return func(c *Claims) error {
		c.Set(StepClaim, v)
		return nil
	}
}

// WithSSH returns an Options function that sets the step claim with the ssh
// property in the value.
func WithSSH(v interface{}) Options {
	return WithStep(map[string]interface{}{
		"ssh": v,
	})
}

// WithConfirmationFingerprint returns an Options function that sets the cnf
// claim with the given CSR fingerprint.
func WithConfirmationFingerprint(fp string) Options {
	return func(c *Claims) error {
		c.Set(ConfirmationClaim, map[string]string{
			"x5rt#S256": fp,
		})
		return nil
	}
}

// WithFingerprint returns an Options function that the cnf claims with
// "x5rt#S256" representing the fingerprint of the CSR
func WithFingerprint(v any) Options {
	return func(c *Claims) error {
		var data []byte
		switch vv := v.(type) {
		case *x509.CertificateRequest:
			data = vv.Raw
		case ssh.PublicKey:
			data = vv.Marshal()
		default:
			return fmt.Errorf("unsupported fingerprint for %T", v)
		}

		fp, err := fingerprint.New(data, crypto.SHA256, fingerprint.Base64RawURLFingerprint)
		if err != nil {
			return err
		}
		c.Set(ConfirmationClaim, map[string]string{
			"x5rt#S256": fp,
		})
		return nil
	}
}

// WithValidity validates boundary inputs and sets the 'nbf' (NotBefore) and
// 'exp' (expiration) options.
func WithValidity(notBefore, expiration time.Time) Options {
	return func(c *Claims) error {
		now := time.Now().UTC()
		if expiration.Before(notBefore) {
			return errors.Errorf("nbf < exp: nbf=%v, exp=%v", notBefore, expiration)
		}
		requestedDelay := notBefore.Sub(now)
		if requestedDelay > MaxValidityDelay {
			return errors.Errorf("requested validity delay is too long: 'requested validity delay'=%v, 'max validity delay'=%v", requestedDelay, MaxValidityDelay)
		}
		requestedValidity := expiration.Sub(notBefore)
		if requestedValidity < MinValidity {
			return errors.Errorf("requested token validity is too short: 'requested token validity'=%v, 'minimum token validity'=%v", requestedValidity, MinValidity)
		} else if requestedValidity > MaxValidity {
			return errors.Errorf("requested token validity is too long: 'requested token validity'=%v, 'maximum token validity'=%v", requestedValidity, MaxValidity)
		}
		c.NotBefore = jose.NewNumericDate(notBefore)
		c.Expiry = jose.NewNumericDate(expiration)
		return nil
	}
}

// WithIssuer returns an Options function that sets the issuer to use in the
// token claims. If Issuer is not used the default issuer will be used.
func WithIssuer(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("issuer cannot be empty")
		}
		c.Issuer = s
		return nil
	}
}

// WithSubject returns an Options that sets the subject to use in the token
// claims.
func WithSubject(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("subject cannot be empty")
		}
		c.Subject = s
		return nil
	}
}

// WithAudience returns a Options that sets the audience to use in the token
// claims. If Audience is not used the default audience will be used.
func WithAudience(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("audience cannot be empty")
		}
		c.Audience = append(jose.Audience{}, s)
		return nil
	}
}

// WithJWTID returns a Options that sets the jwtID to use in the token
// claims. If WithJWTID is not used a random identifier will be used.
func WithJWTID(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("jwtID cannot be empty")
		}
		c.ID = s
		return nil
	}
}

// WithKid returns a Options that sets the header kid claims.
// If WithKid is not used a thumbprint using SHA256 will be used.
func WithKid(s string) Options {
	return func(c *Claims) error {
		if s == "" {
			return errors.New("kid cannot be empty")
		}
		c.SetHeader("kid", s)
		return nil
	}
}

// WithX5CFile returns a Options that sets the header x5c claims.
func WithX5CFile(certFile string, key interface{}) Options {
	return func(c *Claims) error {
		certs, err := pemutil.ReadCertificateBundle(certFile)
		if err != nil {
			return err
		}
		certStrs, err := jose.ValidateX5C(certs, key)
		if err != nil {
			return errors.Wrap(err, "error validating x5c certificate chain and key for use in x5c header")
		}
		c.SetHeader("x5c", certStrs)
		return nil
	}
}

// WithX5CCerts returns a Options that sets the header x5c claims from a cert in memory
func WithX5CCerts(certs []*x509.Certificate, key interface{}) Options {
	return func(c *Claims) error {
		certStrs, err := jose.ValidateX5C(certs, key)
		if err != nil {
			return errors.Wrap(err, "error validating x5c certificate chain and key for use in x5c header")
		}
		c.SetHeader("x5c", certStrs)
		return nil
	}
}

var pemCertPrefix = []byte("-----BEGIN")

// WithNebulaCert returns a Options that sets the nebula header.
func WithNebulaCert(certFile string, anyKey any) Options {
	return func(c *Claims) error {
		b, err := os.ReadFile(certFile)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", certFile)
		}
		if bytes.HasPrefix(b, pemCertPrefix) {
			block, _ := pem.Decode(b)
			if block == nil || block.Type != nebula.CertBanner {
				return errors.Errorf("error reading %s: not a proper nebula certificate", certFile)
			}
			b = block.Bytes
		}
		crt, err := nebula.UnmarshalNebulaCertificate(b)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", certFile)
		}

		var key []byte
		var curve nebula.Curve
		switch k := anyKey.(type) {
		case x25519.PrivateKey:
			key = []byte(k)
			curve = nebula.Curve_CURVE25519
		case ed25519.PrivateKey:
			key = []byte(k)
			curve = nebula.Curve_CURVE25519
		case []byte:
			key = k
			curve = nebula.Curve_CURVE25519
		case *ecdsa.PrivateKey:
			pk, err := k.ECDH()
			if err != nil {
				return fmt.Errorf("failed transforming to ECDH key: %w", err)
			}
			key = pk.Bytes()
			curve = nebula.Curve_P256
		case *ecdh.PrivateKey:
			key = k.Bytes()
			curve = nebula.Curve_P256
		default:
			return errors.Errorf("key content is not a valid nebula key; got type %T", anyKey)
		}

		if err := crt.VerifyPrivateKey(curve, key); err != nil {
			return errors.Wrapf(err, "error validating %s", certFile)
		}

		c.SetHeader("nebula", b)
		return nil
	}
}

// WithX5CInsecureFile returns a Options that sets the header x5cAllowInvalid claims.
// The `x5c` claims can only be accessed by running a method on the jose Token
// which validates the certificate chain before returning it. This option serves
// a use case where the user would prefer not to validate the certificate chain
// before returning it. Presumably the user would then perform their own validation.
// NOTE: here be dragons. Use WithX5CFile unless you know what you are doing.
func WithX5CInsecureFile(certFile string, key interface{}) Options {
	return func(c *Claims) error {
		certs, err := pemutil.ReadCertificateBundle(certFile)
		if err != nil {
			return err
		}
		certStrs, err := jose.ValidateX5C(certs, key)
		if err != nil {
			return errors.Wrap(err, "error validating x5c certificate chain and key for use in x5c header")
		}
		c.SetHeader(jose.X5cInsecureKey, certStrs)
		return nil
	}
}

// WithX5CInsecureCerts returns a Options that sets the header x5cAllowInvalid claims using the cert in memory
func WithX5CInsecureCerts(certs []*x509.Certificate, key interface{}) Options {
	return func(c *Claims) error {
		certStrs, err := jose.ValidateX5C(certs, key)
		if err != nil {
			return errors.Wrap(err, "error validating x5c certificate chain and key for use in x5c header")
		}
		c.SetHeader(jose.X5cInsecureKey, certStrs)
		return nil
	}
}

// WithSSHPOPFile returns a Options that sets the header sshpop claims.
func WithSSHPOPFile(certFile string, key interface{}) Options {
	return func(c *Claims) error {
		certStrs, err := jose.ValidateSSHPOP(certFile, key)
		if err != nil {
			return errors.Wrap(err, "error validating SSH certificate and key for use in sshpop header")
		}
		c.SetHeader("sshpop", certStrs)
		return nil
	}
}
