package sshutil

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli/internal/cast"
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
	Signature             Signature
	Serial                uint64
	ValidAfter            time.Time
	ValidBefore           time.Time
	Principals            []string
	CriticalOptions       map[string]string
	Extensions            map[string]string
}

type Signature struct {
	Type  string
	Value []byte
	Rest  []byte `json:",omitempty"`
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

	validAfter = time.Unix(cast.Int64(cert.ValidAfter), 0)
	if cert.ValidBefore != ssh.CertTimeInfinity {
		validBefore = time.Unix(cast.Int64(cert.ValidBefore), 0)
	}

	return &CertificateInspect{
		Type:                  certType,
		KeyName:               cert.Type(),
		KeyID:                 cert.KeyId,
		KeyAlgo:               algo,
		KeyFingerprint:        sum,
		SigningKeyAlgo:        sigAlgo,
		SigningKeyFingerprint: sigSum,
		Signature: Signature{
			Type:  cert.Signature.Format,
			Value: cert.Signature.Blob,
			Rest:  cert.Signature.Rest,
		},
		Serial:          cert.Serial,
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Principals:      cert.ValidPrincipals,
		CriticalOptions: cert.CriticalOptions,
		Extensions:      cert.Extensions,
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
	fp := ssh.FingerprintSHA256(key)
	typ, _, err := publicKeyTypeAndSize(key)
	if err != nil {
		return "", "", err
	}

	return typ, fp, nil
}
