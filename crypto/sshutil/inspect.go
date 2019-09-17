package sshutil

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

// using the same layout than ssh-keygen
const certificateInspectLayout = "2006-01-02T15:04:05"

// CertificateInspect contains details of an ssh.Certificate in human readable
// format.
type CertificateInspect struct {
	Type                  string
	KeyName               string
	KeyID                 string
	KeyAlgo               string
	KeyFingerprint        string
	SigningKeyAlgo        string
	SigningKeyFingerprint string
	Serial                uint64
	ValidAfter            time.Time
	ValidBefore           time.Time
	Principals            []string
	CriticalOptions       map[string]string
	Extensions            map[string]string
}

// InspectCertificate returns a CertificateInspect with the properties of the
// given ssh.Certificate.
func InspectCertificate(cert *ssh.Certificate) (*CertificateInspect, error) {
	var certType string
	var validAfter, validBefore time.Time

	switch cert.CertType {
	case ssh.HostCert:
		certType = "host"
	case ssh.UserCert:
		certType = "user"
	default:
		certType = "unknown"
	}

	algo, sum, err := inspectPublicKey(cert.Key)
	if err != nil {
		return nil, err
	}
	sigAlgo, sigSum, err := inspectPublicKey(cert.SignatureKey)
	if err != nil {
		return nil, err
	}

	validAfter = time.Unix(int64(cert.ValidAfter), 0)
	if cert.ValidBefore != ssh.CertTimeInfinity {
		validBefore = time.Unix(int64(cert.ValidBefore), 0)
	}

	return &CertificateInspect{
		Type:                  certType,
		KeyName:               cert.Type(),
		KeyID:                 cert.KeyId,
		KeyAlgo:               algo,
		KeyFingerprint:        sum,
		SigningKeyAlgo:        sigAlgo,
		SigningKeyFingerprint: sigSum,
		Serial:                cert.Serial,
		ValidAfter:            validAfter,
		ValidBefore:           validBefore,
		Principals:            cert.ValidPrincipals,
		CriticalOptions:       cert.CriticalOptions,
		Extensions:            cert.Extensions,
	}, nil
}

// Validity returns a human version of the validity of the certificate. It
// returns the dates using the local time zone to behave as ssh-keygen.
func (c *CertificateInspect) Validity() string {
	if c.ValidBefore.IsZero() {
		return "forever"
	}
	return fmt.Sprintf("from %s to %s",
		c.ValidAfter.Local().Format(certificateInspectLayout),
		c.ValidBefore.Local().Format(certificateInspectLayout),
	)
}

func inspectPublicKey(key ssh.PublicKey) (string, string, error) {
	pub, err := PublicKey(key)
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256(key.Marshal())
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	switch k := pub.(type) {
	case *dsa.PublicKey:
		return "DSA", fp, nil
	case *rsa.PublicKey:
		return "RSA", fp, nil
	case *ecdsa.PublicKey:
		return "ECDSA", fp, nil
	case ed25519.PublicKey:
		return "ED25519", fp, nil
	default:
		return "", "", errors.Errorf("unsupported public key %T", k)
	}
}
