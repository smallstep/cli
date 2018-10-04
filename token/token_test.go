package token

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/maraino/dbg"
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
		{"ok", fields{jose.Claims{}, nil}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyNDBjYjhlYTNmYjdhY2Y4MzI1MGFmYjFiMzJkODk0OTczODdkM2ZjNjkwNjMyZGE5NzhkYzYxMTg1NWQ2MDQiLCJ0eXAiOiJKV1QifQ.e30.c5GDK-miVOn-mnyews5OrMCyp1246hhADPjgz3hGI4ReibEq0-rs5xrN-Tjm3ANmtFZDugB9FYeGLQ-vMWBv6t39wagIjqcr0iBeNWLQ9DOItUO2DniZ913SNVZc_Efcg0o48EaXXEWpkF1G1f0ENnvXVzw5JWAaFe0_3LIa1IJoL51wM6H76rHJgYOZ1P42PQuCemRS2Fsol-pA1ihZycAFxX-MkOmt406SecaNJRlf4prsWJDZr3ugRLFvLiDM1NfbSmNoOsm0LHBi9GZMmSVnvQdlN6akVh8kd3S9p2DDCJ87wHYvrXPtrDU5iGIMbEwIoWcygShbbnNSnssfRw", false},
		{"ok one audience", fields{jose.Claims{Audience: jose.Audience{"value"}}, nil}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyNDBjYjhlYTNmYjdhY2Y4MzI1MGFmYjFiMzJkODk0OTczODdkM2ZjNjkwNjMyZGE5NzhkYzYxMTg1NWQ2MDQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ2YWx1ZSJ9.JQ7l7R7zts_6nvFy7HcHqK9TnGO92uuXeXYixmu7b3q2KCbv8xcy90zbM-I-LnYPe678xFaMqX7w-nAPKm9DWGzj1TkbVBtNVpwCjVuHV1WcxOkJ5TftvYsHQjz6AGvUaFcSErfsE6UxRplzZWBnPtYGlLlL5dm4XAin-7GsNPUgTR0gOMLt_dn-s0jHzUy_yrr23ULso4E1uv7A9WCWJoQM2yCpiNewNZol0kf2iRMDS4I49cmqHp_1i2bQHDBTkxks_87z3Tw4YZ9KK1_GzvO6-FJ-V6VInCTCKg6eyRam_eKKcz9vaTAW7YZyrqB6gKbpWtaAPfB90NNtcX0j4w", false},
		{"ok multiple audiences", fields{jose.Claims{Audience: jose.Audience{"foo", "bar"}}, nil}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyNDBjYjhlYTNmYjdhY2Y4MzI1MGFmYjFiMzJkODk0OTczODdkM2ZjNjkwNjMyZGE5NzhkYzYxMTg1NWQ2MDQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiZm9vIiwiYmFyIl19.n1q6o38f-ks1brDrR_PhY1c0woVIVysLbP2MJtQvZVs0y28d5y4-RQD29tl-K2VxcotM9Gg9CDsbaLsZb-KvE9Y0S2Nv9OltJ91DsHdtF3S6P1-PjI48XZKP1Tehl5AKUY2wzES0_Q3rKodF7bx1yJdkAMaiCY6Ip6ILhXnEJYIOEbabD1GrHieObaAHbLb2NX-0TS1aFIA9_bar9aCIkHf47JhL9ERIoFwAlZzV6Ds1AIuAJ_E8_YTHifREfpcs2MAn3WVFSVFUrIqtXLVD_-NBb_6ujkGmOxs4fdkcKw2XW0VVj9Opfha5PwjtAndEjhb_-FyPY8zHK2sxkCCHsA", false},
		{"ok with empty payload", fields{jose.Claims{}, map[string]interface{}{}}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyNDBjYjhlYTNmYjdhY2Y4MzI1MGFmYjFiMzJkODk0OTczODdkM2ZjNjkwNjMyZGE5NzhkYzYxMTg1NWQ2MDQiLCJ0eXAiOiJKV1QifQ.e30.c5GDK-miVOn-mnyews5OrMCyp1246hhADPjgz3hGI4ReibEq0-rs5xrN-Tjm3ANmtFZDugB9FYeGLQ-vMWBv6t39wagIjqcr0iBeNWLQ9DOItUO2DniZ913SNVZc_Efcg0o48EaXXEWpkF1G1f0ENnvXVzw5JWAaFe0_3LIa1IJoL51wM6H76rHJgYOZ1P42PQuCemRS2Fsol-pA1ihZycAFxX-MkOmt406SecaNJRlf4prsWJDZr3ugRLFvLiDM1NfbSmNoOsm0LHBi9GZMmSVnvQdlN6akVh8kd3S9p2DDCJ87wHYvrXPtrDU5iGIMbEwIoWcygShbbnNSnssfRw", false},
		{"ok with payload", fields{jose.Claims{}, map[string]interface{}{"foo": "bar"}}, args{"RS256", rsaKey}, "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyNDBjYjhlYTNmYjdhY2Y4MzI1MGFmYjFiMzJkODk0OTczODdkM2ZjNjkwNjMyZGE5NzhkYzYxMTg1NWQ2MDQiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIifQ.Nyb_EJIdMplEUGr31n76qsxMCmzU5B7zIPJouazWICaUIZxt9xnH6DzmlC80ltrAh0vOKEgaEZVfWejoNZwM1cfzgq6nrHoGWJ99aLRxkVGYtZPbbM8zwAoo0V1v-Y6cK7AvSkcjWQeLgHlp6sVMHhyk6x4DKd6n0h-3JrhVj_zWCndyigsnLPqrOf_TadsSHonBFO7sb7tg6p4bTrHSxLFDQ6gEgMErit8ynDC0wloq4ESY5xpF1yLvoY3fLBcnAOKCAmuViHrdS8DVAs1TPk6GIHILBfKzaTnu9KdNu-eZDAZyj7HCiXTG1wxEqFh_xPOEWZldil69iAns3ZsG3w", false},
		{"fail with public key", fields{jose.Claims{}, nil}, args{"RS256", rsaKey.(*rsa.PrivateKey).Public()}, "", true},
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
				dbg.DD(err)
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

	edKey, err := pemutil.Read("../crypto/pemutil/testdata/pkcs8/openssl.ed25519.pem")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok rsa", args{rsaKey}, "a0ef495278c1c09388e22e9dfa630e347990c2b5449dd186759bb210830faf81", false},
		{"ok es", args{esKey}, "05801440beb95b721a6d9ca5d13250abcf83f7ae4e23c273597a38e800cd56a9", false},
		{"fail with public", args{rsaKey.(*rsa.PrivateKey).Public()}, "", true},
		{"fail with unsupported", args{edKey}, "", true},
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
