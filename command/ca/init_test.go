package ca

import (
	"reflect"
	"testing"

	_ "go.step.sm/crypto/kms/azurekms"
)

func TestDNSListValidate(t *testing.T) {
	tests := []struct {
		name     string
		dnsValue string
		wantErr  bool
	}{
		{
			name:     "dns can't start with -",
			dnsValue: "-ca.smallstep.com",
			wantErr:  true,
		},
		{
			name:     "dns can't contain spaces",
			dnsValue: "ca.small step.com",
			wantErr:  true,
		},
		{
			name:     "dns label can't be over 63 octects long",
			dnsValue: "ca.s0000000m0000000000a0000000000000000000000000000000000000l000000000l0000000000.com",
			wantErr:  true,
		},

		{
			name:     "dns can't be over 255 octets long",
			dnsValue: "1123456789012345678901233456789012345678901234567834567890123456789012345678345678901234567890123456783456789012345678901234567845678901234567890123456789012345678901234567890123456789012345678901234567890234567890.smalls345678901234567890123456783456789012345678901234567834567890123456789012345678tep.com",
			wantErr:  true,
		},

		{
			name:     "dns can't end with -",
			dnsValue: "ca.smallstep-.com",
			wantErr:  true,
		},
		{
			name:     "dns can't contain _",
			dnsValue: "c_a.smallstep.com",
			wantErr:  true,
		},

		{
			name:     "an element is empty at the end",
			dnsValue: "elem,",
			wantErr:  true,
		},
		{
			name:     "an element is empty at the begining",
			dnsValue: "elem,",
			wantErr:  true,
		},
		{
			name:     "an element is empty in the middle",
			dnsValue: "elem,,elem",
			wantErr:  true,
		},
		{
			name:     "dns OK",
			dnsValue: "ca.smallstep.com",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DNSListValidate()(tt.dnsValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("DNSListValidate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

}

func Test_processDNSValue(t *testing.T) {
	tests := []struct {
		name     string
		dnsValue string
		want     []string
		wantErr  bool
	}{
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
