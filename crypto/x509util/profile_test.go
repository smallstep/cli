package x509util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func mustParseRSAKey(t *testing.T, filename string) *rsa.PrivateKey {
	t.Helper()

	b, err := ioutil.ReadFile("test_files/noPasscodeCa.key")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("error decoding %s", filename)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decodeCertificateFile(t *testing.T, filename string) *x509.Certificate {
	t.Helper()
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("error decoding pem")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8
	for i := range bitString {
		b := bitString[len(bitString)-i-1]
		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}
	return 0
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
}

func oidFromExtKeyUsage(eku x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// RFC 5280, 4.2.1.10
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

type generalSubtree struct {
	Name string `asn1:"tag:2,optional,ia5"`
}

type userExt struct {
	FName string `asn1:"tag:0,optional,ia5"`
	LName string `asn1:"tag:1,optional,ia5"`
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	return asn1.Marshal(rawValues)
}

func Test_base_CreateCertificate(t *testing.T) {
	issCert := mustParseCertificate(t, "test_files/noPasscodeCa.crt")
	issKey := mustParseRSAKey(t, "test_files/noPasscodeCa.key")
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)

	type test struct {
		p   Profile
		err error
	}
	tests := map[string]func(*testing.T) test{
		"fail/no-subject-pub-key": func(t *testing.T) test {
			p, err := NewLeafProfile("test.smallstep.com", issCert, issKey)
			assert.FatalError(t, err)
			lp, ok := p.(*Leaf)
			assert.Fatal(t, ok)
			lp.base.subPub = nil
			return test{
				p:   lp,
				err: errors.New("Profile does not have subject public key. Need to call 'profile.GenerateKeyPair(...)' or use setters to populate keys"),
			}
		},
		"fail/no-issuer-priv-key": func(t *testing.T) test {
			p, err := NewLeafProfile("test.smallstep.com", issCert, issKey)
			assert.FatalError(t, err)
			lp, ok := p.(*Leaf)
			assert.Fatal(t, ok)
			lp.base.issPriv = nil
			return test{
				p:   lp,
				err: errors.New("Profile does not have issuer private key. Use setters to populate this field"),
			}
		},
		"ok": func(t *testing.T) test {
			p, err := NewLeafProfile("test.smallstep.com", issCert, issKey, WithPublicKey(ecdsaKey.Public()))
			assert.FatalError(t, err)
			lp, ok := p.(*Leaf)
			assert.Fatal(t, ok)

			// KeyUsage Extension
			keyUsageExt := pkix.Extension{}
			keyUsageExt.Id = asn1.ObjectIdentifier{2, 5, 29, 15}
			keyUsageExt.Critical = true
			ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign
			var a [2]byte
			a[0] = reverseBitsInAByte(byte(ku))
			a[1] = reverseBitsInAByte(byte(ku >> 8))
			l := 1
			if a[1] != 0 {
				l = 2
			}
			bitString := a[:l]
			keyUsageExt.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
			assert.FatalError(t, err)

			// BasicConstraints Extension
			bcExt := pkix.Extension{}
			bcExt.Id = asn1.ObjectIdentifier{2, 5, 29, 19}
			bcExt.Critical = false
			bcExt.Value, err = asn1.Marshal(basicConstraints{IsCA: true, MaxPathLen: 1})
			assert.FatalError(t, err)

			// ExtendedKeyUSage Extension
			extKeyUsageExt := pkix.Extension{}
			extKeyUsageExt.Id = asn1.ObjectIdentifier{2, 5, 29, 37}
			extKeyUsageExt.Critical = false
			var oids []asn1.ObjectIdentifier
			var eku []x509.ExtKeyUsage = []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageMicrosoftKernelCodeSigning,
			}
			for _, u := range eku {
				oid, ok := oidFromExtKeyUsage(u)
				assert.Fatal(t, ok)
				oids = append(oids, oid)
			}
			// Add unknown extkeyusage
			oids = append(oids, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4})
			extKeyUsageExt.Value, err = asn1.Marshal(oids)
			assert.FatalError(t, err)

			// Add SubjectAltName extension
			sanExt := pkix.Extension{}
			sanExt.Id = oidExtSubjectAltName
			sanExt.Value, err = marshalSANs([]string{"foo.internal"}, nil, []net.IP{net.ParseIP("127.0.0.1")}, []*url.URL{{Scheme: "https", Host: "google.com"}})
			assert.FatalError(t, err)

			// NameConstraints Extension
			ncExt := pkix.Extension{}
			ncExt.Id = asn1.ObjectIdentifier{2, 5, 29, 30}
			ncExt.Critical = true
			var out nameConstraints
			permittedDNSDomains := []string{"foo", "bar", "baz"}
			out.Permitted = make([]generalSubtree, len(permittedDNSDomains))
			for i, permitted := range permittedDNSDomains {
				out.Permitted[i] = generalSubtree{Name: permitted}
			}
			ncExt.Value, err = asn1.Marshal(out)
			assert.FatalError(t, err)

			// Unknown Extension
			uExt := pkix.Extension{}
			uExt.Id = asn1.ObjectIdentifier{1, 2, 3, 4, 5}
			uExt.Critical = false
			uExt.Value = []byte("foo")

			u2Ext := pkix.Extension{}
			u2Ext.Id = asn1.ObjectIdentifier{1, 1, 13, 1, 2, 4, 15, 17, 1, 3, 1, 2, 4, 1}
			u2Ext.Critical = true
			u2Ext.Value, err = asn1.Marshal(userExt{FName: "max", LName: "furman"})
			assert.FatalError(t, err)

			lp.base.ext = []pkix.Extension{keyUsageExt, bcExt, extKeyUsageExt, sanExt, ncExt, uExt, u2Ext}
			return test{
				p: lp,
			}
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := tt(t)
			if certBytes, err := tc.p.CreateCertificate(); err != nil {
				if assert.NotNil(t, tc.err, "expected no error but got '%s'", err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					cert, err := x509.ParseCertificate(certBytes)
					assert.FatalError(t, err)
					assert.Equals(t, cert.Subject.CommonName, "test.smallstep.com")
					assert.Equals(t, cert.KeyUsage, x509.KeyUsageDigitalSignature)

					assert.Len(t, 2, cert.ExtKeyUsage)
					assert.Equals(t, cert.ExtKeyUsage[0], x509.ExtKeyUsageServerAuth)
					assert.Equals(t, cert.ExtKeyUsage[1], x509.ExtKeyUsageClientAuth)

					assert.False(t, cert.BasicConstraintsValid)
					assert.False(t, cert.IsCA)
					assert.False(t, cert.MaxPathLenZero)
					assert.Equals(t, cert.MaxPathLen, 0)

					assert.Len(t, 0, cert.PermittedDNSDomains)

					assert.Len(t, 0, cert.DNSNames)
					assert.Len(t, 0, cert.EmailAddresses)
					assert.Len(t, 0, cert.IPAddresses)
					assert.Len(t, 0, cert.URIs)

					nonStdExts := 0
					for _, ext := range cert.Extensions {
						if _, ok := oidStdExtHashMap[ext.Id.String()]; !ok {
							nonStdExts++
						}
					}
					assert.Equals(t, nonStdExts, 2)
				}
			}
		})
	}
}

func Test_base_CreateCertificate_KeyEncipherment(t *testing.T) {
	// Issuer
	iss := mustParseCertificate(t, "test_files/noPasscodeCa.crt")
	issPriv := mustParseRSAKey(t, "test_files/noPasscodeCa.key")

	mustCreateLeaf := func(key interface{}) Profile {
		p, err := NewLeafProfile("test.smallstep.com", iss, issPriv, WithPublicKey(key))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Keys and certs
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaProfile := mustCreateLeaf(ecdsaKey.Public())

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaProfile := mustCreateLeaf(rsaKey.Public())

	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Profile := mustCreateLeaf(ed25519PubKey)

	tests := []struct {
		name                string
		profile             Profile
		wantKeyEncipherment bool
	}{
		{"ecdsa", ecdsaProfile, false},
		{"rsa", rsaProfile, true},
		{"ed25519", ed25519Profile, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.profile.CreateCertificate()
			if err != nil {
				t.Errorf("base.CreateCertificate() error = %v", err)
				return
			}
			cert, err := x509.ParseCertificate(got)
			if err != nil {
				t.Errorf("error parsing certificate: %v", err)
			} else {
				ku := cert.KeyUsage & x509.KeyUsageKeyEncipherment
				switch {
				case tt.wantKeyEncipherment && ku == 0:
					t.Errorf("base.CreateCertificate() keyUsage = %x, want %x", cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
				case !tt.wantKeyEncipherment && ku != 0:
					t.Errorf("base.CreateCertificate() keyUsage = %x, want %x", cert.KeyUsage, x509.KeyUsageDigitalSignature)
				}
			}
		})
	}
}

func Test_generateSubjectKeyID(t *testing.T) {
	ecdsaCrt := decodeCertificateFile(t, "test_files/google.crt")
	rsaCrt := decodeCertificateFile(t, "test_files/smallstep.crt")
	ed25519Crt := decodeCertificateFile(t, "test_files/ed25519.crt")

	type args struct {
		pub crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ecdsa", args{ecdsaCrt.PublicKey}, ecdsaCrt.SubjectKeyId, false},
		{"rsa", args{rsaCrt.PublicKey}, rsaCrt.SubjectKeyId, false},
		{"ed25519", args{ed25519Crt.PublicKey}, ed25519Crt.SubjectKeyId, false},
		{"fail", args{[]byte("fail")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateSubjectKeyID(tt.args.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateSubjectKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateSubjectKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}
