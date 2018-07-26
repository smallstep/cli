package x509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/pkg/x509"
)

const (
	defaultDuration = time.Hour * 24 * 365
)

var (
	// DefaultCertValidity is the minimum validity of an end-entity (not root or intermediate) certificate.
	DefaultCertValidity = 24 * time.Hour
	// DefaultRootCertValidity is the default validity of a root certificate in the step PKI.
	DefaultRootCertValidity = time.Hour * 24 * 365 * 10
	// DefaultIntermediateCertValidity is the default validity of a root certificate in the step PKI.
	DefaultIntermediateCertValidity = time.Hour * 24 * 365 * 10

	// TLS Options

	// DefaultTLSMinVersion default minimum version of TLS.
	DefaultTLSMinVersion = TLSVersion(1.2)
	// DefaultTLSMaxVersion default maximum version of TLS.
	DefaultTLSMaxVersion = TLSVersion(1.2)
	// DefaultTLSRenegotiation default TLS connection renegotiation policy.
	DefaultTLSRenegotiation = false // Never regnegotiate.
	// DefaultTLSCipherSuites specifies default step ciphersuite(s).
	DefaultTLSCipherSuites = CipherSuites{
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	// ApprovedTLSCipherSuites smallstep approved ciphersuites.
	ApprovedTLSCipherSuites = CipherSuites{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	}
)

// PkixName allows us to add our own methods to pkix.Name
type PkixName pkix.Name

// CertTemplate allows us to add our own methods to x509.Certificate
type CertTemplate x509.Certificate

// PkixNameBuilder for organizing pkix fields.
type PkixNameBuilder struct {
	Country, Organization, OrganizationalUnit     *string
	Locality, Province, StreetAddress, PostalCode *string
	SerialNumber, CommonName                      *string
}

// Now is a helper function that returns the current time with the location
// set to UTC.
func Now() time.Time {
	return time.Now().UTC()
}

// Country generates a function that modifies the Country value
// of a certificate name struct.
// Takes a pointer to a comma separated string of countries
// (e.g. " ecuador,italy,brazil")
// Returns a function that will modify, in-place, a CertTemplate.
func Country(countries string) func(*PkixName) error {
	return func(pn *PkixName) error {
		if countries == "" {
			return errors.Errorf("countries cannot be empty")
		}
		// appends countries to existing list
		for _, c := range strings.Split(countries, ",") {
			pn.Country = append(pn.Country, c)
		}
		return nil
	}
}

// Locality generates a function that modifies the Country value
// of a certificate name struct.
// Takes a pointer to a comma separated string of localities
// (e.g. " ecuador,italy,brazil")
// Returns a function that will modify, in-place, a CertTemplate.
func Locality(localities string) func(*PkixName) error {
	return func(pn *PkixName) error {
		if localities == "" {
			return errors.Errorf("localities cannot be empty")
		}
		// appends localities to existing list
		for _, l := range strings.Split(localities, ",") {
			pn.Locality = append(pn.Locality, l)
		}
		return nil
	}
}

// CommonName generates a function that modifies the CommonName value
// of a certificate name struct.
// Takes a pointer to a common name string.
// Returns a function that will modify, in-place, a CertTemplate.
func CommonName(common string) func(*PkixName) error {
	return func(pn *PkixName) error {
		if common == "" {
			return errors.Errorf("common cannot be empty")
		}
		pn.CommonName = common
		return nil
	}
}

// Organization generates a function that modifies the Organization value
// of a certificate name struct.
// Takes a pointer to a comma separated string of organizations
// (e.g. " ecuador,italy,brazil")
// Returns a function that will modify, in-place, a CertTemplate.
func Organization(orgs string) func(*PkixName) error {
	return func(pn *PkixName) error {
		if orgs == "" {
			return errors.Errorf("orgs cannot be empty")
		}
		// appends organizations to existing list
		for _, o := range strings.Split(orgs, ",") {
			pn.Organization = append(pn.Organization, o)
		}
		return nil
	}
}

// NewPkixName generates a new PkixName struct.
// Takes an arbitrary number of augmenting functions each of which modifies
// a PkixName. A default PkixName is created and then the optional
// augmenter functions are applied one after another in the order in which they
// appear as parameters.
// Returns the address of a new PkixName and an error object that will be
// nil on success or contain error data on failure.
func NewPkixName(options ...func(*PkixName) error) (*PkixName, error) {
	pn := &PkixName{}

	for _, op := range options {
		err := op(pn)
		if err != nil {
			return nil, err
		}
	}

	return pn, nil
}

// Hosts generates a function that modifies the IPAddresses and DNSNames values
// of a certificate.
// Takes a pointer to a comma separated string of hostnames
// (e.g. "127.0.0.1,smallstep.com,blog.smallstep.com")
// Returns a function that will modify, in-place, a CertTemplate.
func Hosts(hosts string) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		if hosts == "" {
			return errors.New("hosts cannot be empty")
		}
		hostsL := strings.Split(hosts, ",")
		for _, h := range hostsL {
			if h == "" {
				continue
			} else if ip := net.ParseIP(h); ip != nil {
				ct.IPAddresses = append(ct.IPAddresses, ip)
			} else {
				ct.DNSNames = append(ct.DNSNames, h)
			}
		}
		return nil
	}
}

// NotBeforeAfter generates a function that modifies the NotBefore and NotAfter
// values of a certificate.
// Takes a pair of arguments used to compute the window of time during which
// the certificate should be valid.
// Returns a function that will modify, in-place, a CertTemplate.
func NotBeforeAfter(from time.Time, duration time.Duration) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		if from.IsZero() {
			ct.NotBefore = Now()
		} else {
			ct.NotBefore = from
		}

		switch {
		case duration < 0:
			return errors.New("Duration must be greater than 0")
		case duration == 0:
			ct.NotAfter = ct.NotBefore.Add(defaultDuration)
		default:
			ct.NotAfter = ct.NotBefore.Add(duration)
		}

		return nil
	}
}

// SerialNumber generates a function that modifies the SerialNumber value of
// a CertTemplate.
// Takes an argument that will be used to set the SerialNumber.
// Returns a function that will modify, in-place, a CertTemplate.
func SerialNumber(sn *string) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		// If sn is empty then generate a random serial number.
		if sn == nil || len(*sn) == 0 {
			return errors.Errorf("SerialNumber cannot be nil or empty")
		}

		ct.SerialNumber = new(big.Int)
		ct.SerialNumber.SetString(*sn, 10)
		if _, succ := ct.SerialNumber.SetString(*sn, 10); !succ {
			return errors.Errorf("Failed to parse serial number: %s",
				*sn)
		}
		return nil
	}
}

// Issuer generates a function that modifies the Issuer value of
// a CertTemplate.
// Takes an argument that will be used to populate the Issuer pkix.Name.
// Returns a function that will modify, in-place, a CertTemplate.
func Issuer(pn PkixName) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		ct.Issuer = pkix.Name(pn)
		return nil
	}
}

// Subject generates a function that modifies the Subject value of
// a CertTemplate.
// Takes an argument that will be used to populate the Subject pkix.Name.
// Returns a function that will modify, in-place, a CertTemplate.
func Subject(pn PkixName) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		ct.Subject = pkix.Name(pn)
		return nil
	}
}

// CRLSign generates a function that modifies the KeyUsage bitmap value of a
// CertTemplate.
func CRLSign(c bool) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		if c {
			ct.KeyUsage |= x509.KeyUsageCRLSign
		} else {
			ct.KeyUsage &= ^(x509.KeyUsageCRLSign)
		}
		return nil
	}
}

// BasicConstraints generates a function that modifies the BasicConstraintsValid,
// IsCA, MaxPathLen, and MaxPathLenZero fields of a CertTemplate.
//
// If BasicConstraintsValid==true then the next two fields are valid.
// MaxPathLenZero indicates that BasicConstraintsValid==true and
// MaxPathLen==0 should be interpreted as an actual maximum path length
// of zero. Otherwise, that combination is interpreted as MaxPathLen
// not being set.
func BasicConstraints(bcv bool, isCA bool, maxPathLen int) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		if maxPathLen < 0 {
			return errors.Errorf("MaxPathLen must be >= 0")
		}
		if bcv {
			ct.BasicConstraintsValid = true
			ct.isCAHelper(isCA)
			ct.MaxPathLen = maxPathLen
			if maxPathLen == 0 {
				ct.MaxPathLenZero = true
			}
		} else {
			if isCA {
				return errors.Errorf("isCA must be `false` if `BasicConstraintsValid==false`")
			}
			if maxPathLen != 0 {
				return errors.Errorf("maxPathLen should be set to 0 if `BasicConstraintsValid==false`")
			}
			ct.BasicConstraintsValid = false
			ct.isCAHelper(false)
			ct.MaxPathLen = 0
			ct.MaxPathLenZero = false
		}
		return nil
	}
}

func (ct *CertTemplate) isCAHelper(isCA bool) {
	if isCA {
		ct.IsCA = true
		ct.KeyUsage |= x509.KeyUsageCertSign
	} else {
		ct.IsCA = false
		ct.KeyUsage &= ^(x509.KeyUsageCertSign)
	}
}

// ExtKeyUsage overwrites the extended key usage slice of a CertTemplate
func ExtKeyUsage(eku []x509.ExtKeyUsage) func(*CertTemplate) error {
	return func(ct *CertTemplate) error {
		ct.ExtKeyUsage = eku
		return nil
	}
}

// NewCertTemplate generates and returns a new CertTemplate struct.
// Takes an arbitrary number of augmenting functions each of which modifies
// a CertTemplate. A default CertTemplate is created and then the optional
// augmenter functions are applied one after another in the order in which they
// were submitted.
// Returns the address of a new CertTemplate and an error object which will
// the nil on success and contain the reason and location of the failure.
func NewCertTemplate(options ...func(*CertTemplate) error) (*CertTemplate, error) {
	var err error
	notBefore := Now()

	ct := &CertTemplate{
		IsCA:      false,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(defaultDuration),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
	}

	for _, op := range options {
		err = op(ct)
		if err != nil {
			return nil, err
		}
	}

	if ct.SerialNumber == nil {
		// TODO figure out how to test rand w/out threading as another arg
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		ct.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
		// TODO error condition untested -- hard to test w/o mocking rand
		if err != nil {
			return nil, errors.Wrap(err, "Failed to generate serial number")
		}
	}

	return ct, nil
}

// Compare compares the calling CertTemplate to the one provided as an argument.
// Returns nil if the two are equal, otherwise returns an error describing the diff.
// NOTE: this method avoids comparing a number of fields that are inconvenient or difficult
// to compare for equality. Check the `IgnoreFields` call below to check if the
// field you would like to check is being ignored.
func (ct CertTemplate) Compare(other CertTemplate) error {
	var diff string

	if diff = cmp.Diff(CertTemplate(ct), other,
		cmpopts.IgnoreFields(ct, "Extensions", "Issuer.Names",
			"NotBefore", "NotAfter", "PublicKey", "Raw", "RawIssuer",
			"RawSubject", "RawSubjectPublicKeyInfo", "RawTBSCertificate",
			"SerialNumber", "Signature", "Subject.Names")); len(diff) != 0 {
		return errors.Errorf("data mismatch -- %s", diff)
	}

	if other.NotBefore.Before(ct.NotBefore.Add(-time.Second*10)) ||
		ct.NotBefore.After(ct.NotBefore.Add(time.Second*10)) {
		return errors.Errorf("NotBefore mismatch -- expected: `%s`, but got: `%s`",
			ct.NotBefore, other.NotBefore)
	}
	if ct.NotAfter.Before(other.NotAfter.Add(-time.Second*10)) ||
		ct.NotAfter.After(other.NotAfter.Add(time.Second*10)) {
		return errors.Errorf("NotAfter mismatch -- expected: `%s`, but got: `%s`",
			ct.NotAfter, other.NotAfter)
	}
	return nil
}

// MergeASN1DN fills empty fields of a pkix.Name with default ASN1DN settings.
// If the field is already set (with non-empty value) then do not overwrite
// with default value, otherwise overwrite.
// TODO: test
func MergeASN1DN(n *pkix.Name, asn1dn *ASN1DN) error {
	if n == nil || asn1dn == nil {
		return errors.New("both arguments to mergeASN1DN must be non-nil")
	}
	if len(n.Country) == 0 && asn1dn.Country != "" {
		n.Country = append(n.Country, asn1dn.Country)
	}
	if len(n.Organization) == 0 && asn1dn.Organization != "" {
		n.Organization = append(n.Organization, asn1dn.Organization)
	}
	if len(n.OrganizationalUnit) == 0 && asn1dn.OrganizationalUnit != "" {
		n.OrganizationalUnit = append(n.OrganizationalUnit, asn1dn.OrganizationalUnit)
	}
	if len(n.Locality) == 0 && asn1dn.Locality != "" {
		n.Locality = append(n.Locality, asn1dn.Locality)
	}
	if len(n.Province) == 0 && asn1dn.Province != "" {
		n.Province = append(n.Province, asn1dn.Province)
	}
	if len(n.StreetAddress) == 0 && asn1dn.StreetAddress != "" {
		n.StreetAddress = append(n.StreetAddress, asn1dn.StreetAddress)
	}
	return nil
}

// FromCSR generates a CertTemplate from a x509 certificate signing request.
func FromCSR(csr *x509.CertificateRequest, options ...func(*CertTemplate) error) (*CertTemplate, error) {
	ct, err := NewCertTemplate(Hosts(csr.Subject.CommonName),
		NotBeforeAfter(Now(), DefaultCertValidity),
		ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}),
		Subject(PkixName(csr.Subject)))
	if err != nil {
		return nil, err
	}
	for _, op := range options {
		err = op(ct)
		if err != nil {
			return nil, err
		}
	}
	return ct, nil
}

// FromCert generates a CertTemplate from a x509 certificate.
func FromCert(cert *x509.Certificate, issuer pkix.Name) (*CertTemplate, error) {
	return NewCertTemplate(Hosts(cert.Subject.CommonName),
		NotBeforeAfter(Now(), DefaultCertValidity),
		ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}),
		Issuer(PkixName(issuer)), Subject(PkixName(cert.Subject)))
}
