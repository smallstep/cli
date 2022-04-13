package cautils

import (
	"testing"

	"github.com/smallstep/certificates/authority/config"
)

func TestOfflineCA_CaURL(t *testing.T) {
	tests := []struct {
		name   string
		config config.Config
		want   string
	}{
		{
			name: "ok/dns",
			config: config.Config{
				DNSNames: []string{"ca.smallstep.com"},
			},
			want: "https://ca.smallstep.com",
		},
		{
			name: "ok/ipv4",
			config: config.Config{
				DNSNames: []string{"127.0.0.1", "127.0.0.2"},
			},
			want: "https://127.0.0.1",
		},
		{
			name: "ok/ipv6",
			config: config.Config{
				DNSNames: []string{"::1", "ca.smallstep.com"},
			},
			want: "https://[::1]",
		},
		{
			name: "ok/ipv6-brackets",
			config: config.Config{
				DNSNames: []string{"[::1]", "127.0.0.1"},
			},
			want: "https://[::1]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OfflineCA{
				config: tt.config,
			}
			if got := c.CaURL(); got != tt.want {
				t.Errorf("OfflineCA.CaURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOfflineCA_Audience(t *testing.T) {
	tests := []struct {
		name    string
		config  config.Config
		tokType int
		want    string
	}{
		{
			name: "ok/dns-revoke",
			config: config.Config{
				DNSNames: []string{"ca.smallstep.com"},
			},
			tokType: RevokeType,
			want:    "https://ca.smallstep.com/revoke",
		},
		{
			name: "ok/dns-ssh-revoke",
			config: config.Config{
				DNSNames: []string{"ca.smallstep.com"},
			},
			tokType: SSHRevokeType,
			want:    "https://ca.smallstep.com/ssh/revoke",
		},
		{
			name: "ok/dns-ssh-rekey",
			config: config.Config{
				DNSNames: []string{"ca.smallstep.com"},
			},
			tokType: SSHRekeyType,
			want:    "https://ca.smallstep.com/ssh/rekey",
		},
		{
			name: "ok/dns-renew",
			config: config.Config{
				DNSNames: []string{"ca.smallstep.com"},
			},
			tokType: RenewType,
			want:    "https://ca.smallstep.com/renew",
		},
		{
			name: "ok/ipv4-sign",
			config: config.Config{
				DNSNames: []string{"127.0.0.1"},
			},
			tokType: SSHHostSignType,
			want:    "https://127.0.0.1/ssh/sign",
		},
		{
			name: "ok/ipv6-ssh-renew",
			config: config.Config{
				DNSNames: []string{"::1"},
			},
			tokType: SSHRenewType,
			want:    "https://[::1]/ssh/renew",
		},
		{
			name: "ok/ipv6-bracketed-sign",
			config: config.Config{
				DNSNames: []string{"[::1]"},
			},
			tokType: SignType,
			want:    "https://[::1]/sign",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OfflineCA{
				config: tt.config,
			}
			if got := c.Audience(tt.tokType); got != tt.want {
				t.Errorf("OfflineCA.Audience() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOfflineCA_GetCaURL(t *testing.T) {
	type fields struct {
		config config.Config
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"ok", fields{config.Config{DNSNames: []string{"ca.com"}}}, "https://ca.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OfflineCA{
				config: tt.fields.config,
			}
			if got := c.GetCaURL(); got != tt.want {
				t.Errorf("OfflineCA.GetCaURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
