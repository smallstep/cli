package flags

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
	"go.step.sm/crypto/fingerprint"
)

func TestParseCaURL(t *testing.T) {
	// This is just to get a simple CLI context
	app := &cli.App{}
	set := flag.NewFlagSet("contrive", 0)
	_ = set.String("ca-url", "", "")
	ctx := cli.NewContext(app, set, nil)

	type test struct {
		name, caURL, ret string
		err              error
	}
	tests := []test{
		{name: "fail/empty", caURL: "", ret: "", err: errors.New("' ' requires the '--ca-url' flag")},
		{name: "fail/badCaURL", caURL: "git://git@github.com", ret: "", err: errors.New("invalid value 'git://git@github.com' for flag '--ca-url'; must have https scheme")},
		{name: "ok", caURL: "https://ca.smallstep.com:8080", ret: "https://ca.smallstep.com:8080"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx.Set("ca-url", tc.caURL)
			ret, err := ParseCaURL(ctx)
			if err != nil && assert.NotNil(t, tc.err, fmt.Sprintf("expected no error but got <%s>", err)) {
				assert.HasPrefix(t, err.Error(), tc.err.Error())
			} else if assert.Nil(t, tc.err, fmt.Sprintf("expected error <%s> but got nil", tc.err)) {
				assert.Equals(t, ret, tc.ret)
			}
		})
	}
}

func TestParseCaURLIfExists(t *testing.T) {
	// This is just to get a simple CLI context
	app := &cli.App{}
	set := flag.NewFlagSet("contrive", 0)
	_ = set.String("ca-url", "", "")
	ctx := cli.NewContext(app, set, nil)

	type test struct {
		name, caURL, ret string
		err              error
	}
	tests := []test{
		{name: "fail/badCaURL", caURL: "git://git@github.com", ret: "", err: errors.New("invalid value 'git://git@github.com' for flag '--ca-url'; must have https scheme")},
		{name: "ok/empty", caURL: "", ret: ""},
		{name: "ok", caURL: "https://ca.smallstep.com:8080", ret: "https://ca.smallstep.com:8080"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx.Set("ca-url", tc.caURL)
			ret, err := ParseCaURLIfExists(ctx)
			if err != nil && assert.NotNil(t, tc.err, fmt.Sprintf("expected no error but got <%s>", err)) {
				assert.HasPrefix(t, err.Error(), tc.err.Error())
			} else if assert.Nil(t, tc.err, fmt.Sprintf("expected error <%s> but got nil", tc.err)) {
				assert.Equals(t, ret, tc.ret)
			}
		})
	}
}

func Test_parseCaURL(t *testing.T) {
	// This is just to get a simple CLI context
	app := &cli.App{}
	set := flag.NewFlagSet("contrive", 0)
	_ = set.String("ca-url", "", "")
	ctx := cli.NewContext(app, set, nil)

	type test struct {
		name, caURL, ret string
		err              error
	}
	tests := []test{
		{name: "fail/invalidURL", caURL: "#$%@#://&%^&%#$^#$", ret: "", err: errors.New("invalid value '#$%@#://&%^&%#$^#$' for flag '--ca-url'; invalid URL")},
		{name: "fail/invalidScheme-git", caURL: "git://git@github.com", ret: "", err: errors.New("invalid value 'git://git@github.com' for flag '--ca-url'; must have https scheme")},
		{name: "fail/invalidScheme-http", caURL: "http://ca.smallstep.com:8080", ret: "", err: errors.New("invalid value 'http://ca.smallstep.com:8080' for flag '--ca-url'; must have https scheme")},
		{name: "ok", caURL: "https://ca.smallstep.com:8080", ret: "https://ca.smallstep.com:8080"},
		{name: "ok/provide-scheme", caURL: "ca.smallstep.com:8080", ret: "https://ca.smallstep.com:8080"},
		{name: "ok/ipv4", caURL: "https://127.0.0.1:8080", ret: "https://127.0.0.1:8080"},
		{name: "ok/ipv4-no-port", caURL: "https://127.0.0.1", ret: "https://127.0.0.1"},
		{name: "ok/ipv4-no-scheme", caURL: "127.0.0.1:8080", ret: "https://127.0.0.1:8080"},
		{name: "ok/ipv4-no-port-no-scheme", caURL: "127.0.0.1", ret: "https://127.0.0.1"},
		{name: "ok/ipv6-bracketed", caURL: "https://[::1]:8080", ret: "https://[::1]:8080"},
		{name: "ok/ipv6-bracketed-no-port", caURL: "https://[::1]", ret: "https://[::1]"},
		{name: "ok/ipv6-bracketed-no-scheme", caURL: "[::1]:8080", ret: "https://[::1]:8080"},
		{name: "ok/ipv6-bracketed-no-port-no-scheme", caURL: "[::1]", ret: "https://[::1]"},
		{name: "ok/ipv6-non-bracketed", caURL: "https://::1:8080", ret: "https://[::1]:8080"},
		{name: "ok/ipv6-non-bracketed-no-port", caURL: "https://::1", ret: "https://[::1]"},
		{name: "ok/ipv6-non-bracketed-no-scheme", caURL: "::1:8080", ret: "https://[::1]:8080"},
		{name: "ok/ipv6-non-bracketed-no-port-no-scheme", caURL: "::1", ret: "https://[::1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ret, err := parseCaURL(ctx, tc.caURL)
			if err != nil && assert.NotNil(t, tc.err, fmt.Sprintf("expected no error but got <%s>", err)) {
				assert.HasPrefix(t, err.Error(), tc.err.Error())
			} else if assert.Nil(t, tc.err, fmt.Sprintf("expected error <%s> but got nil", tc.err)) {
				assert.Equals(t, ret, tc.ret)
			}
		})
	}
}

func TestParseTemplateData(t *testing.T) {
	tempDir := t.TempDir()
	write := func(t *testing.T, data []byte) string {
		f, err := os.CreateTemp(tempDir, "parseTemplateData")
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(data)
		if err1 := f.Close(); err1 != nil && err == nil {
			t.Fatal(err1)
		}
		if err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}

	type args struct {
		setData     []string
		setFileData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    json.RawMessage
		wantErr bool
	}{
		{"ok nil", args{nil, nil}, nil, false},
		{"ok set", args{[]string{"foo=bar"}, nil}, []byte(`{"foo":"bar"}`), false},
		{"ok set empty", args{[]string{"foo="}, nil}, []byte(`{"foo":""}`), false},
		{"ok set int", args{[]string{"foo=123"}, nil}, []byte(`{"foo":123}`), false},
		{"ok set int string", args{[]string{`foo="123"`}, nil}, []byte(`{"foo":"123"}`), false},
		{"ok set object", args{[]string{`foo={"foo":"bar"}`}, nil}, []byte(`{"foo":{"foo":"bar"}}`), false},
		{"ok set multiple", args{[]string{"foo=bar", "bar=123", "zar={}"}, nil}, []byte(`{"bar":123,"foo":"bar","zar":{}}`), false},
		{"ok set overwrite", args{[]string{"foo=bar1", "foo=bar2"}, nil}, []byte(`{"foo":"bar2"}`), false},
		{"ok set-file", args{nil, []byte(`{"foo":"bar","bar":123,"zar":{}}`)}, []byte(`{"bar":123,"foo":"bar","zar":{}}`), false},
		{"ok set and set-file", args{[]string{"foo=bar-set", "bar=123"}, []byte(`{"foo":"bar-file","zar":{"foo":"bar"}}`)}, []byte(`{"bar":123,"foo":"bar-set","zar":{"foo":"bar"}}`), false},
		{"fail set", args{[]string{"foo"}, nil}, nil, true},
		{"fail set-file json", args{nil, []byte(`{"foo":"bar}`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet(t.Name(), 0)

			if tt.args.setData != nil {
				value := cli.StringSlice(tt.args.setData)
				set.Var(&value, "set", "")
			}
			if tt.args.setFileData != nil {
				fileName := write(t, tt.args.setFileData)
				set.String("set-file", fileName, "")
			}

			got, err := ParseTemplateData(cli.NewContext(app, set, nil))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTemplateData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTemplateData() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseTemplateData_missing(t *testing.T) {
	tempDir := t.TempDir()
	app := &cli.App{}
	set := flag.NewFlagSet(t.Name(), 0)
	set.String("set-file", filepath.Join(tempDir, "missing"), "")

	_, err := ParseTemplateData(cli.NewContext(app, set, nil))
	if err == nil {
		t.Errorf("ParseTemplateData() error = %v, wantErr true", err)
	}
}

func TestParseFingerprintFormat(t *testing.T) {
	type args struct {
		format string
	}
	tests := []struct {
		name    string
		args    args
		want    fingerprint.Encoding
		wantErr bool
	}{
		{"hex", args{"hex"}, fingerprint.HexFingerprint, false},
		{"base64", args{"base64"}, fingerprint.Base64Fingerprint, false},
		{"base64url", args{"base64url"}, fingerprint.Base64URLFingerprint, false},
		{"base64-url", args{"base64-url"}, fingerprint.Base64URLFingerprint, false},
		{"base64urlraw", args{"base64urlraw"}, fingerprint.Base64RawURLFingerprint, false},
		{"base64url-raw", args{"base64url-raw"}, fingerprint.Base64RawURLFingerprint, false},
		{"base64-url-raw", args{"base64-url-raw"}, fingerprint.Base64RawURLFingerprint, false},
		{"base64raw", args{"base64raw"}, fingerprint.Base64RawFingerprint, false},
		{"base64-raw", args{"base64-raw"}, fingerprint.Base64RawFingerprint, false},
		{"emoji", args{"emoji"}, fingerprint.EmojiFingerprint, false},
		{"emojisum", args{"emojisum"}, fingerprint.EmojiFingerprint, false},
		{"unknown", args{"unknown"}, 0, true},
		{"empty", args{""}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFingerprintFormat(tt.args.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFingerprintFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseFingerprintFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFirstStringOf(t *testing.T) {
	getAppSet := func() (*cli.App, *flag.FlagSet) {
		app := &cli.App{}
		set := flag.NewFlagSet("contrive", 0)
		return app, set
	}
	tests := []struct {
		name       string
		getContext func() *cli.Context
		inputs     []string
		want       string
		wantName   string
	}{
		{
			name: "no-flags-empty",
			getContext: func() *cli.Context {
				app, set := getAppSet()
				//_ = set.String("ca-url", "", "")
				return cli.NewContext(app, set, nil)
			},
			inputs:   []string{"foo", "bar"},
			want:     "",
			wantName: "foo",
		},
		{
			name: "return-first-set-flag",
			getContext: func() *cli.Context {
				app, set := getAppSet()
				_ = set.String("foo", "", "")
				_ = set.String("bar", "", "")
				_ = set.String("baz", "", "")
				ctx := cli.NewContext(app, set, nil)
				ctx.Set("bar", "test1")
				ctx.Set("baz", "test2")
				return ctx
			},
			inputs:   []string{"foo", "bar", "baz"},
			want:     "test1",
			wantName: "bar",
		},
		{
			name: "return-first-default-flag",
			getContext: func() *cli.Context {
				app, set := getAppSet()
				_ = set.String("foo", "", "")
				_ = set.String("bar", "", "")
				_ = set.String("baz", "test1", "")
				ctx := cli.NewContext(app, set, nil)
				return ctx
			},
			inputs:   []string{"foo", "bar", "baz"},
			want:     "test1",
			wantName: "baz",
		},
		{
			name: "all-empty",
			getContext: func() *cli.Context {
				app, set := getAppSet()
				_ = set.String("foo", "", "")
				_ = set.String("bar", "", "")
				_ = set.String("baz", "", "")
				ctx := cli.NewContext(app, set, nil)
				return ctx
			},
			inputs:   []string{"foo", "bar", "baz"},
			want:     "",
			wantName: "foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.getContext()
			val, name := FirstStringOf(ctx, tt.inputs...)
			require.Equal(t, tt.want, val)
			require.Equal(t, tt.wantName, name)
		})
	}
}
