package ca

import (
	"crypto/x509"
	"net"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func mustParseURI(t *testing.T, u string) (parsed *url.URL) {
	t.Helper()
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func Test_mergeSans(t *testing.T) {
	type args struct {
		sans []string
		csr  *x509.CertificateRequest
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty",
			args: args{
				sans: nil,
				csr:  &x509.CertificateRequest{},
			},
			want: []string{},
		},
		{
			name: "context-only",
			args: args{
				sans: []string{"www.example.com"},
				csr:  &x509.CertificateRequest{},
			},
			want: []string{"www.example.com"},
		},
		{
			name: "csr-only",
			args: args{
				sans: nil,
				csr: &x509.CertificateRequest{
					DNSNames: []string{"www.example.com"},
				},
			},
			want: []string{"www.example.com"},
		},
		{
			name: "full",
			args: args{
				sans: []string{"www1.test.local", "mail+1@local", "127.0.0.1", "https://www1.test.local", "www1.test.local", "mail+1@local", "127.0.0.1", "https://www1.test.local"},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"www.example.com", "www1.test.local", "www.example.com"},
					IPAddresses: []net.IP{
						net.ParseIP("127.0.0.2"),
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					},
					EmailAddresses: []string{"mail+2@local", "mail+1@local", "mail+2@local"},
					URIs: []*url.URL{
						mustParseURI(t, "https://www2.test.local"),
						mustParseURI(t, "https://www1.test.local"),
						mustParseURI(t, "https://www2.test.local"),
					},
				},
			},
			want: []string{"www1.test.local", "mail+1@local", "127.0.0.1", "https://www1.test.local",
				"www.example.com", "127.0.0.2", "mail+2@local", "https://www2.test.local"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeSans(tt.args.sans, tt.args.csr); !cmp.Equal(tt.want, got) {
				t.Errorf("mergeSans() diff =\n%s", cmp.Diff(tt.want, got))
			}
		})
	}
}
