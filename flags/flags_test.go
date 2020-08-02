package flags

import (
	"errors"
	"flag"
	"fmt"
	"testing"

	"github.com/smallstep/assert"
	"github.com/urfave/cli"
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
