package utils

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// Fail prints out the error struct if STEPDEBUG is true otherwise it just
// prints out the error message. Finally, it exits with an error code of 1.
func Fail(err error) {
	if err != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

// CompleteURL parses and validates the given URL. It supports general
// URLs like https://ca.smallstep.com[:port][/path], and incomplete URLs like
// ca.smallstep.com[:port][/path].
func CompleteURL(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", errors.Wrapf(err, "error parsing url '%s'", rawurl)
	}

	// URLs are generally parsed as:
	// [scheme:][//[userinfo@]host][/]path[?query][#fragment]
	// But URLs that do not start with a slash after the scheme are interpreted as
	// scheme:opaque[?query][#fragment]
	if u.Opaque == "" {
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		if u.Host == "" {
			// rawurl looks like ca.smallstep.com or ca.smallstep.com/1.0/sign
			if u.Path != "" {
				parts := strings.SplitN(u.Path, "/", 2)
				u.Host = parts[0]
				if len(parts) == 2 {
					u.Path = parts[1]
				} else {
					u.Path = ""
				}
				return CompleteURL(u.String())
			}
			return "", errors.Errorf("error parsing url '%s'", rawurl)
		}
		return u.String(), nil
	}
	// scheme:opaque[?query][#fragment]
	// rawurl looks like ca.smallstep.com:443 or ca.smallstep.com:443/1.0/sign
	return CompleteURL("https://" + rawurl)
}

// GetInsecureTransport returns a transport that bypasses TLS server auth.
func GetInsecureTransport() *http.Transport {
	return &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
