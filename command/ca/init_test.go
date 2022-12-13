package ca

import (
	"reflect"
	"testing"

	_ "go.step.sm/crypto/kms/azurekms"
)

func Test_processDNSValue(t *testing.T) {
	tests := []struct {
		name     string
		dnsValue string
		want     []string
		wantErr  bool
	}{

		{
			name:     "fail/empty",
			dnsValue: "",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "fail/empty-multiple",
			dnsValue: ",,",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "fail/dns",
			dnsValue: "ca.smallstep.com:8443",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "fail/ipv4",
			dnsValue: "127.0.0.1:8080",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "fail/ipv6",
			dnsValue: ":::1",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "ok/dns",
			dnsValue: "ca.smallstep.com",
			want:     []string{"ca.smallstep.com"},
			wantErr:  false,
		},
		{
			name:     "ok/multi-dns",
			dnsValue: "ca.smallstep.com,ca.localhost",
			want:     []string{"ca.smallstep.com", "ca.localhost"},
			wantErr:  false,
		},
		{
			name:     "ok/multi-dns-with-skip",
			dnsValue: "ca.smallstep.com,ca.localhost,,test.localhost",
			want:     []string{"ca.smallstep.com", "ca.localhost", "test.localhost"},
			wantErr:  false,
		},
		{
			name:     "ok/multi-space-dns",
			dnsValue: "ca.smallstep.com ca.localhost",
			want:     []string{"ca.smallstep.com", "ca.localhost"},
			wantErr:  false,
		},
		{
			name:     "ok/ipv4",
			dnsValue: "127.0.0.1",
			want:     []string{"127.0.0.1"},
			wantErr:  false,
		},
		{
			name:     "ok/multi-ipv4",
			dnsValue: "127.0.0.1,127.0.0.2",
			want:     []string{"127.0.0.1", "127.0.0.2"},
			wantErr:  false,
		},
		{
			name:     "ok/ipv6-no-brackets",
			dnsValue: "::1",
			want:     []string{"::1"},
			wantErr:  false,
		},
		{
			name:     "ok/multi-ipv6-no-brackets",
			dnsValue: "::1,::2",
			want:     []string{"::1", "::2"},
			wantErr:  false,
		},
		{
			name:     "ok/ipv6-with-brackets",
			dnsValue: "[::1]",
			want:     []string{"::1"},
			wantErr:  false,
		},
		{
			name:     "ok/multi-ipv6-with-brackets",
			dnsValue: "[::1] [::2]",
			want:     []string{"::1", "::2"},
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processDNSValue(tt.dnsValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("processDNSValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("processDNSValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
