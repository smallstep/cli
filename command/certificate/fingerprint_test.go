package certificate

import (
	"github.com/smallstep/cli/crypto/x509util"
	"testing"
)

func TestGetFingerprintFormat(t *testing.T) {
	type args struct {
		format string
	}
	tests := []struct {
		name    string
		args    args
		want    x509util.FingerprintEncoding
		wantErr bool
	}{
		{
			"hex",
			args{
				"HEX",
			},
			x509util.HexFingerprint,
			false,
		},
		{
			"base64",
			args{
				"base64",
			},
			x509util.Base64Fingerprint,
			false,
		},
		{
			"base64url",
			args{
				"base64Url",
			},
			x509util.Base64UrlFingerprint,
			false,
		},
		{
			"base64-url",
			args{
				"base64-URL",
			},
			x509util.Base64UrlFingerprint,
			false,
		},
		{
			"unknown",
			args{
				"unknown",
			},
			x509util.HexFingerprint,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getFingerprintFormat(tt.args.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("getFingerprintFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getFingerprintFormat() got = %v, want %v", got, tt.want)
			}
		})
	}
}
