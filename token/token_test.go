package token

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/cli/crypto/randutil"

	"golang.org/x/crypto/ed25519"

	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
)

func TestClaims_Set(t *testing.T) {
	type fields struct {
		Claims      jose.Claims
		ExtraClaims map[string]interface{}
	}
	type args struct {
		key   string
		value interface{}
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Claims
	}{
		{"ok nil", fields{jose.Claims{}, nil}, args{"key", "value"}, &Claims{ExtraClaims: map[string]interface{}{"key": "value"}}},
		{"ok empty", fields{jose.Claims{}, make(map[string]interface{})}, args{"key", "value"}, &Claims{ExtraClaims: map[string]interface{}{"key": "value"}}},
		{"ok not empty", fields{jose.Claims{}, map[string]interface{}{"foo": "bar"}}, args{"key", "value"}, &Claims{ExtraClaims: map[string]interface{}{"key": "value", "foo": "bar"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Claims{
				Claims:      tt.fields.Claims,
				ExtraClaims: tt.fields.ExtraClaims,
			}
			c.Set(tt.args.key, tt.args.value)
			if !reflect.DeepEqual(c, tt.want) {
				t.Errorf("Options claims = %v, want %v", c, tt.want)
			}
		})
	}
}

func TestClaims_Sign(t *testing.T) {
	type fields struct {
		Claims      jose.Claims
		ExtraClaims map[string]interface{}
	}
	type args struct {
		alg jose.SignatureAlgorithm
		key interface{}
	}

	rsaKey, err := pemutil.Read("../crypto/pemutil/testdata/openssl.rsa2048.pem")
	if err != nil {
		t.Fatal(err)
	}

	badKey, err := rsa.GenerateKey(rand.Reader, 123)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{"ok", fields{jose.Claims{}, nil}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6IkoyUThZSzJsM2wyZmgwYURYLUxHLWlxTmlneVkwZHhUNHM2TkgtOFFmVTAiLCJ0eXAiOiJKV1QifQ.e30.0FbvZdz3qUv-k9AmGerLh5c1LbT6XRBUwFKe7iU0GU7fZnDYAmVyTIkyxwhc6zD5K5rURfqnGXKYNOa4JVUQ7T6S0fZOVFYI3pBExDImi3it9JTXWwDpDle6GqESQfpyZMdIWBB16B6vf8S4K7ZlKmAD00F6f1SB-Vzd_bV_kgdjTkBaHl3DSGRJdn8UBbGrkmrxm7iBogLKXtYMxDQLzIqZF3mMzZiTWNVELpoLOO5cAPXpcdVQ24a2u66KU5WM5n-GxBBYW7JwEDmFi7AoXWCixDlPlBTOVr2BIta99U9e7QwiD3OvEAnjrqUHHtsaJ-kcSxLiRM49CfnJZm_cjg", false},
		{"ok one audience", fields{jose.Claims{Audience: jose.Audience{"value"}}, nil}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6IkoyUThZSzJsM2wyZmgwYURYLUxHLWlxTmlneVkwZHhUNHM2TkgtOFFmVTAiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ2YWx1ZSJ9.o1OyBGmRNi0YEiaMNYnJrSgegbQePHc267Y-fDEyRKxa8LQzSL7eZekUuI1VsSGsBJxWUBu9WI9XHjCEHCrhQst9rNiYaEG4ooz0SCS7JSii4CedvhgI0PPfw5g1uTmkHQ-1qxM9cUfRFM0sCd3ULffb8qdvg8l6CEwYKS0nCZmIH8rt8I9Z24k6gs85budt0g0ZM9iwH-irmFwTsn6ZbVfKgggeEPNXEMvcjsofch3p9-n30kkicsyAZMo4oTD1Z8nnX4JlghGpt1kjRh79kNXO7KdQKHNcyus7Hk2Cpf304cMT5yuxezhUJDl4-gqPE8Im4OvLvMmUibjWHiVfQw", false},
		{"ok multiple audiences", fields{jose.Claims{Audience: jose.Audience{"foo", "bar"}}, nil}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6IkoyUThZSzJsM2wyZmgwYURYLUxHLWlxTmlneVkwZHhUNHM2TkgtOFFmVTAiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiZm9vIiwiYmFyIl19.ykdEryzCfOi1GzpM9VrYw7tCGlzK3u_0sehk4Cx_o3TiDz82dbyMfPQMAr_2agVPeNvnkPIadZutyt5rFyj-Dn0W1svQpwG7PKqSJKLjSBBiBT1gbJuCQBAs7dzmsJVqcq9i4UmgIKH4EQsvFWoxA52PSD9TtvfhKtFYP23deJZ22ViqBrbYjaz1nQG0Lm_hX8RyOoEWem25n_mwPUtYuKHNy9rekwHanpyEUiehCpIzuZgMGcZ6_lln1BYlPMWkfyTz6K1uRMeZC3phWdSgW4JTvFp7xRGiC8L-pAboPoj7t8GArZgm2aGnF2OAtIw1eJ8GiaH3EBS7Adnw8CUb9w", false},
		{"ok with empty payload", fields{jose.Claims{}, map[string]interface{}{}}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6IkoyUThZSzJsM2wyZmgwYURYLUxHLWlxTmlneVkwZHhUNHM2TkgtOFFmVTAiLCJ0eXAiOiJKV1QifQ.e30.0FbvZdz3qUv-k9AmGerLh5c1LbT6XRBUwFKe7iU0GU7fZnDYAmVyTIkyxwhc6zD5K5rURfqnGXKYNOa4JVUQ7T6S0fZOVFYI3pBExDImi3it9JTXWwDpDle6GqESQfpyZMdIWBB16B6vf8S4K7ZlKmAD00F6f1SB-Vzd_bV_kgdjTkBaHl3DSGRJdn8UBbGrkmrxm7iBogLKXtYMxDQLzIqZF3mMzZiTWNVELpoLOO5cAPXpcdVQ24a2u66KU5WM5n-GxBBYW7JwEDmFi7AoXWCixDlPlBTOVr2BIta99U9e7QwiD3OvEAnjrqUHHtsaJ-kcSxLiRM49CfnJZm_cjg", false},
		{"ok with payload", fields{jose.Claims{}, map[string]interface{}{"foo": "bar"}}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6IkoyUThZSzJsM2wyZmgwYURYLUxHLWlxTmlneVkwZHhUNHM2TkgtOFFmVTAiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIifQ.KFHfeRbE3Xk-EaJee1WIyzNB4J3Ybwt56pnTkArU0a5F8cING1Z2bhrtYFrm8ejJOMwuYBxp3JzZQKvKND363hPuiT-Zz9fF_cYjOAk1lj2yEXHPhUkWKWb91uaCus6F4AgMsacjMWN26cw3fEDdGmitRii2sNUKcM6sf7rpUo2k1hME8PpevEpXtwIecAmxwvQWBaKMXc_stxMnvbTGO_BTbFtmdDwvrqbapHxzRXMJbZcDAyREi_qqLN-2ylBfs-mRtccghrdzuq3ckvFy_7ojBk9bWoxHbcOqL0tDwOu8AOjEMX2GE5zlfqltU_IXVm95xlVObkAsL6buqrdfog", false},
		{"fail with unsupported key", fields{jose.Claims{}, nil}, args{"HS256", []byte("the-key")}, "", true},
		{"fail with wrong alg", fields{jose.Claims{}, nil}, args{"FOOBAR", rsaKey}, "", true},
		{"fail with invalid alg", fields{jose.Claims{}, nil}, args{"HS256", rsaKey}, "", true},
		{"fail on sign", fields{jose.Claims{}, nil}, args{"RS256", badKey}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Claims{
				Claims:      tt.fields.Claims,
				ExtraClaims: tt.fields.ExtraClaims,
			}
			got, err := c.Sign(tt.args.alg, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Claims.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Claims.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func withFixedTime(c *Claims, t time.Time) {
	if c == nil {
		return
	}
	c.IssuedAt = jose.NewNumericDate(t)
}

func TestNewClaims(t *testing.T) {
	type args struct {
		opts []Options
	}

	now := time.Now()
	want := DefaultClaims()
	want.Subject = "subject"
	want.IssuedAt = jose.NewNumericDate(now)
	want.NotBefore = jose.NewNumericDate(now)
	want.Expiry = jose.NewNumericDate(now.Add(10 * time.Minute))

	tests := []struct {
		name    string
		args    args
		want    *Claims
		wantErr bool
	}{
		{"ok", args{[]Options{WithSubject("subject"), WithValidity(now, now.Add(10*time.Minute))}}, want, false},
		{"fail", args{[]Options{WithSubject("")}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewClaims(tt.args.opts...)
			withFixedTime(got, now)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateKeyID(t *testing.T) {
	type args struct {
		priv interface{}
	}

	rsaKey, err := pemutil.Read("../crypto/pemutil/testdata/openssl.rsa1024.pem")
	if err != nil {
		t.Fatal(err)
	}

	esKey, err := pemutil.Read("../crypto/pemutil/testdata/openssl.p256.pem")
	if err != nil {
		t.Fatal(err)
	}

	b, err := randutil.Salt(64)
	if err != nil {
		t.Fatal(err)
	}
	badKey := ed25519.PublicKey(b)

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok rsa", args{rsaKey}, "ntSigdQY4tK8YfL7GB6c4dng8oHeF9NU2ItAIU8kGdg", false},
		{"ok es", args{esKey}, "COu8GPmatXsngf8XdSj5J3aqQotmjs7QR1lll517DxM", false},
		{"fail with unsupported", args{[]byte("the-key")}, "", true},
		{"fail with bad key", args{badKey}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKeyID(tt.args.priv)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GenerateKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}
