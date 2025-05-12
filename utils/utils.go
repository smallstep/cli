package utils

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

var urlPrefixes = map[string]uint16{
	"tcp://":   443,
	"tls://":   443,
	"https://": 443,
	"smtps://": 465,
	"ldaps://": 636,
}

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

// TrimURL returns the host[:port] if the input is a URL, otherwise returns an
// empty string (and 'isURL:false').
//
// If the URL is valid and no port is specified, the default port determined
// by the URL prefix is used.
//
// Examples:
// TrimURL("https://smallstep.com/onboarding") -> "smallstep.com:443", true, nil
// TrimURL("https://ca.smallSTEP.com:8080") -> "ca.smallSTEP.com:8080", true, nil
// TrimURL("./certs/root_ca.crt") -> "", false, nil
// TrimURL("hTtPs://sMaLlStEp.cOm") -> "sMaLlStEp.cOm:443", true, nil
// TrimURL("hTtPs://sMaLlStEp.cOm hello") -> "", false, err{"invalid url"}
func TrimURL(ref string) (string, bool, error) {
	tmp := strings.ToLower(ref)
	for prefix := range urlPrefixes {
		if strings.HasPrefix(tmp, prefix) {
			u, err := url.Parse(ref)
			if err != nil {
				return "", false, fmt.Errorf("error parsing %q: %w", ref, err)
			}
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				port := strconv.FormatUint(uint64(urlPrefixes[prefix]), 10)
				u.Host = net.JoinHostPort(u.Host, port)
			}
			return u.Host, true, nil
		}
	}
	return "", false, nil
}
