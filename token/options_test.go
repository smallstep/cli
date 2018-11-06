package token

import (
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/cli/jose"
)

func TestOptions(t *testing.T) {
	empty := new(Claims)
	now := time.Now()
	tests := []struct {
		name    string
		option  Options
		want    *Claims
		wantErr bool
	}{
		{"WithClaim ok", WithClaim("name", "foo"), &Claims{ExtraClaims: map[string]interface{}{"name": "foo"}}, false},
		{"WithClaim fail", WithClaim("", "foo"), empty, true},
		{"WithRootCA ok", WithRootCA("../crypto/pemutil/testdata/ca.crt"), &Claims{ExtraClaims: map[string]interface{}{"sha": "6908751f68290d4573ae0be39a98c8b9b7b7d4e8b2a6694b7509946626adfe98"}}, false},
		{"WithRootCA fail", WithRootCA("not-exists"), empty, true},
		{"WithValidity ok", WithValidity(now, now.Add(5*time.Minute)), &Claims{Claims: jose.Claims{NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(5 * time.Minute))}}, false},
		{"WithRootCA expired", WithValidity(now, now.Add(-1*time.Second)), empty, true},
		{"WithRootCA long delay", WithValidity(now.Add(MaxValidityDelay+time.Minute), now.Add(MaxValidityDelay+10*time.Minute)), empty, true},
		{"WithRootCA min validity ok", WithValidity(now, now.Add(MinValidity)), &Claims{Claims: jose.Claims{NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(MinValidity))}}, false},
		{"WithRootCA min validity fail", WithValidity(now, now.Add(MinValidity-time.Second)), empty, true},
		{"WithRootCA max validity ok", WithValidity(now, now.Add(MaxValidity)), &Claims{Claims: jose.Claims{NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(MaxValidity))}}, false},
		{"WithRootCA max validity fail", WithValidity(now, now.Add(MaxValidity+time.Second)), empty, true},
		{"WithIssuer ok", WithIssuer("value"), &Claims{Claims: jose.Claims{Issuer: "value"}}, false},
		{"WithIssuer fail", WithIssuer(""), empty, true},
		{"WithSubject ok", WithSubject("value"), &Claims{Claims: jose.Claims{Subject: "value"}}, false},
		{"WithSubject fail", WithSubject(""), empty, true},
		{"WithAudience ok", WithAudience("value"), &Claims{Claims: jose.Claims{Audience: jose.Audience{"value"}}}, false},
		{"WithAudience fail", WithAudience(""), empty, true},
		{"WithJWTID ok", WithJWTID("value"), &Claims{Claims: jose.Claims{ID: "value"}}, false},
		{"WithJWTID fail", WithJWTID(""), empty, true},
		{"WithKid ok", WithKid("value"), &Claims{ExtraHeaders: map[string]interface{}{"kid": "value"}}, false},
		{"WithKid fail", WithKid(""), empty, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := new(Claims)
			err := tt.option(claim)
			if (err != nil) != tt.wantErr {
				t.Errorf("Options error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(claim, tt.want) {
				t.Errorf("Options claims = %v, want %v", claim, tt.want)
			}
		})
	}
}
