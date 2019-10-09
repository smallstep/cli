package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	stepx509 "github.com/smallstep/cli/pkg/x509"
)

const p256Cert = `-----BEGIN CERTIFICATE-----
MIIBbDCCARGgAwIBAgIQB2n32M1trIqbSNO5s4fDszAKBggqhkjOPQQDAjAUMRIw
EAYDVQQDEwlTbWFsbHN0ZXAwHhcNMTkwMzIwMjEzNTQ3WhcNMjkwMzE3MjEzNTQ3
WjAUMRIwEAYDVQQDEwlTbWFsbHN0ZXAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQYWj9HJC5ODzKccPs6PU0J024H1AvD6TZ9OKNCzUtnCL+xCieNoXt+nkz0bWYy
B/l7NZYmiK/fm593cuH6s3OSo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/
BAgwBgEB/wIBATAdBgNVHQ4EFgQUO4vdeQoiwWXxOf0PqR3Q8jHpEcowCgYIKoZI
zj0EAwIDSQAwRgIhAKuPgK9oMG1sfZNRvl+nuih/pClJYkBL8xKn1nZegw8TAiEA
yjfrPADkvXB+8Q+03y+LFpBKT+/Ik/QX0gg5aXV2QCI=
-----END CERTIFICATE-----`

const p256Csr = `-----BEGIN CERTIFICATE REQUEST-----
MIHPMHYCAQAwFDESMBAGA1UEAxMJU21hbGxzdGVwMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEtllRP2ccqN2Civ1XUU4TPjLHqiSN5GQh7QTtQLCjPT6DMsjahEiT
8k34oGNi9MF66GqTwsBWD9HOqgcGqxVZw6AAMAoGCCqGSM49BAMCA0kAMEYCIQDK
mKr4vkMPzu78/2sTOyMt0GVpWV+W7atLk7YhwhnfagIhANq6so7Hk8X16ps2SRAo
GkaGf4tysRN6vKA/Oq77ukaG
-----END CERTIFICATE REQUEST-----`

const ed25519Cert = `-----BEGIN CERTIFICATE-----
MIIBKjCB3aADAgECAhACaDrQ2I9zn60Pt5ctWZE7MAUGAytlcDAUMRIwEAYDVQQD
EwlTbWFsbHN0ZXAwHhcNMTkwMzIwMjEzNDQ0WhcNMjkwMzE3MjEzNDQ0WjAUMRIw
EAYDVQQDEwlTbWFsbHN0ZXAwKjAFBgMrZXADIQDjbJdq67orCi8Alkg6xtApQ879
rYCyjgcGY9Ibu9gbu6NFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQEwHQYDVR0OBBYEFMzQag6BfhEm3JwvmYkHBcjYeEZkMAUGAytlcANBAPA7
gku6S6wxO+E4anCbyzIoc2kmNOKKkjkJhr5nxhpEfsz4i40E8p5YH20V2WQYjtBK
vhhVZulIOs7FAqiU/AU=
-----END CERTIFICATE-----`

const ed25519Csr = `-----BEGIN CERTIFICATE REQUEST-----
MIGTMEcCAQAwFDESMBAGA1UEAxMJU21hbGxzdGVwMCowBQYDK2VwAyEAk+PGnyUh
20sK6UcTkSr+aGC3QVpt4x+uZnW5nASe/UigADAFBgMrZXADQQC/HMU8qPSgh8vY
A0rCTeGgLIR0IJ65tR1CPwyeMZlFpe6AoyM7lIKDxWabZVBau1W8HqFDvhjaxNrE
070Tz9oO
-----END CERTIFICATE REQUEST-----`

func pemBytes(t *testing.T, data string) []byte {
	block, rest := pem.Decode([]byte(data))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding PEM")
	}
	return block.Bytes
}

func TestParseCertificate(t *testing.T) {
	p256Bytes := pemBytes(t, p256Cert)
	ed25519Bytes := pemBytes(t, ed25519Cert)

	p256, err := x509.ParseCertificate(p256Bytes)
	assert.FatalError(t, err)

	edCert, err := stepx509.ParseCertificate(ed25519Bytes)
	assert.FatalError(t, err)
	ed25519 := ToX509Certificate(edCert)

	type args struct {
		asn1Data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{"p256", args{p256Bytes}, p256, false},
		{"ed25519", args{ed25519Bytes}, ed25519, false},
		{"fail", args{nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCertificate(tt.args.asn1Data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCertificateRequest(t *testing.T) {
	p256Bytes := pemBytes(t, p256Csr)
	ed25519Bytes := pemBytes(t, ed25519Csr)

	p256, err := x509.ParseCertificateRequest(p256Bytes)
	assert.FatalError(t, err)

	edCsr, err := stepx509.ParseCertificateRequest(ed25519Bytes)
	assert.FatalError(t, err)
	ed25519 := ToX509CertificateRequest(edCsr)

	type args struct {
		asn1Data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.CertificateRequest
		wantErr bool
	}{
		{"p256", args{p256Bytes}, p256, false},
		{"ed25519", args{ed25519Bytes}, ed25519, false},
		{"fail", args{nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCertificateRequest(tt.args.asn1Data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCertificateRequest() = %v, want %v", got, tt.want)
			}
			if got != nil {
				if err := CheckCertificateRequestSignature(got); err != nil {
					t.Errorf("CheckCertificateRequestSignature() error = %v", err)
					return
				}
			}
		})
	}
}

func TestParseEd25519NoError(t *testing.T) {
	block, rest := pem.Decode([]byte(ed25519Cert))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)
	assert.Equals(t, x509.Ed25519, cert.PublicKeyAlgorithm)
	assert.Equals(t, x509.Ed25519.String(), cert.SignatureAlgorithm.String())
	assert.NotNil(t, cert.PublicKey)
	assert.Len(t, 64, cert.Signature)

	block, rest = pem.Decode([]byte(ed25519Csr))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	assert.FatalError(t, err)
	assert.Equals(t, x509.Ed25519, csr.PublicKeyAlgorithm)
	assert.Equals(t, x509.Ed25519.String(), csr.SignatureAlgorithm.String())
	assert.NotNil(t, csr.PublicKey)
	assert.Len(t, 64, csr.Signature)
}

func TestConvertCertificates(t *testing.T) {
	p256Bytes := pemBytes(t, p256Cert)
	ed25519Bytes := pemBytes(t, ed25519Cert)

	p1, err := x509.ParseCertificate(p256Bytes)
	assert.FatalError(t, err)
	p2, err := stepx509.ParseCertificate(p256Bytes)
	assert.FatalError(t, err)
	assert.Equals(t, p1, ToX509Certificate(p2))
	assert.Equals(t, p2, ToStepX509Certificate(p1))
	assert.Equals(t, p1, ToX509Certificate(ToStepX509Certificate(p1)))
	assert.Equals(t, p2, ToStepX509Certificate(ToX509Certificate(p2)))

	e1, err := stepx509.ParseCertificate(ed25519Bytes)
	assert.FatalError(t, err)
	assert.Equals(t, e1, ToStepX509Certificate(ToX509Certificate(e1)))
}

func TestConvertCertificateRequests(t *testing.T) {
	p256Bytes := pemBytes(t, p256Csr)
	ed25519Bytes := pemBytes(t, ed25519Csr)

	p1, err := x509.ParseCertificateRequest(p256Bytes)
	assert.FatalError(t, err)
	p2, err := stepx509.ParseCertificateRequest(p256Bytes)
	assert.FatalError(t, err)
	assert.Equals(t, p1, ToX509CertificateRequest(p2))
	assert.Equals(t, p2, ToStepX509CertificateRequest(p1))
	assert.Equals(t, p1, ToX509CertificateRequest(ToStepX509CertificateRequest(p1)))
	assert.Equals(t, p2, ToStepX509CertificateRequest(ToX509CertificateRequest(p2)))

	e1, err := stepx509.ParseCertificateRequest(ed25519Bytes)
	assert.FatalError(t, err)
	assert.Equals(t, e1, ToStepX509CertificateRequest(ToX509CertificateRequest(e1)))
}

func TestToStepX509Certificate(t *testing.T) {
	block, rest := pem.Decode([]byte(p256Cert))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	scert, err := stepx509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *stepx509.Certificate
	}{
		{"ok", args{cert}, scert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToStepX509Certificate(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToStepX509Certificate() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestToX509Certificate(t *testing.T) {
	block, rest := pem.Decode([]byte(p256Cert))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	scert, err := stepx509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	type args struct {
		cert *stepx509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{"ok", args{scert}, cert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToX509Certificate(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToX509Certificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToStepX509CertificateRequest(t *testing.T) {
	block, rest := pem.Decode([]byte(p256Csr))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding certificate request")
	}

	cert, err := x509.ParseCertificateRequest(block.Bytes)
	assert.FatalError(t, err)

	scert, err := stepx509.ParseCertificateRequest(block.Bytes)
	assert.FatalError(t, err)

	type args struct {
		cert *x509.CertificateRequest
	}
	tests := []struct {
		name string
		args args
		want *stepx509.CertificateRequest
	}{
		{"ok", args{cert}, scert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToStepX509CertificateRequest(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToStepX509CertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToX509CertificateRequest(t *testing.T) {
	block, rest := pem.Decode([]byte(p256Csr))
	if !assert.Len(t, 0, rest) || !assert.NotNil(t, block) {
		t.Fatal("error decoding certificate request")
	}

	cert, err := x509.ParseCertificateRequest(block.Bytes)
	assert.FatalError(t, err)

	scert, err := stepx509.ParseCertificateRequest(block.Bytes)
	assert.FatalError(t, err)

	type args struct {
		cert *stepx509.CertificateRequest
	}
	tests := []struct {
		name string
		args args
		want *x509.CertificateRequest
	}{
		{"ok", args{scert}, cert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToX509CertificateRequest(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToX509CertificateRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
