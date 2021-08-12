package cautils

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/exec"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/step"

	"github.com/pkg/errors"
)

type bootstrapAPIResponse struct {
	CaURL       string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	RedirectURL string `json:"redirect-url"`
}

// BootstrapTeamAuthority does a request to api.smallstep.com to bootstrap the
// configuration of a given team/authority.
func BootstrapTeamAuthority(ctx *cli.Context, team, authority string) error {
	apiEndpoint := ctx.String("team-url")
	if apiEndpoint == "" {
		// Use the default endpoint..
		u := url.URL{
			Scheme: "https",
			Host:   "api.smallstep.com",
			Path:   "/v1/teams/" + team + "/authorities/" + authority,
		}
		apiEndpoint = u.String()
	} else {
		// The user specified a custom endpoint..
		apiEndpoint = strings.ReplaceAll(apiEndpoint, "<>", team)
		u, err := url.Parse(apiEndpoint)
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", apiEndpoint)
		}
		apiEndpoint = u.String()
	}

	// Using public PKI
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		return errors.Wrap(err, "error getting authority data")
	}
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusNotFound {
			return errors.New("error getting authority data: authority not found")
		}
		return errors.Wrap(readError(resp.Body), "error getting authority data")
	}

	var r bootstrapAPIResponse
	if err := readJSON(resp.Body, &r); err != nil {
		return errors.Wrap(err, "error getting authority data")
	}

	if r.RedirectURL == "" {
		r.RedirectURL = "https://smallstep.com/app/teams/sso/success"
	}

	args := []string{"ca", "bootstrap-helper",
		"--ca-url", r.CaURL,
		"--fingerprint", r.Fingerprint,
		"--redirect-url", r.RedirectURL,
	}

	if step.IsContextEnabled() {
		host, err := getHost(r.CaURL)
		if err != nil {
			return err
		}
		name := ctx.String("context-name")
		if name == "" {
			name = authority + "." + team
		}
		profile := ctx.String("context-profile")
		if profile == "" {
			profile = team
		}
		if err := step.AddContext(&step.Context{
			Name:      name,
			Profile:   profile,
			Authority: host,
		}); err != nil {
			return err
		}
		args = append(args, "--context", name)
	}
	if ctx.Bool("force") {
		args = append(args, "--force")
	}
	if ctx.Bool("install") {
		args = append(args, "--install")
	}
	if _, err := exec.Step(args...); err != nil {
		return errors.Wrap(err, "error getting team data")
	}

	// Set ca-url and root certificate
	ctx.Set("ca-url", r.CaURL)
	ctx.Set("fingerprint", r.Fingerprint)
	ctx.Set("root", pki.GetRootCAPath())
	//ctx.Set("root", "/Users/max/src/github.com/smallstep/cli/.step/authorities/ssh.beta.ca.smallstep.com/certs/root_ca.crt")

	return nil
}

// BootstrapAuthority bootstraps an autority using only the caURL and fingerprint.
func BootstrapAuthority(ctx *cli.Context, caURL, fingerprint string) error {
	args := []string{"ca", "bootstrap-helper",
		"--ca-url", caURL,
		"--fingerprint", fingerprint,
	}

	if step.IsContextEnabled() {
		authority, err := getHost(caURL)
		if err != nil {
			return err
		}
		name := ctx.String("context-name")
		if name == "" {
			name = authority
		}
		profile := ctx.String("context-profile")
		if profile == "" {
			profile = authority
		}
		if err := step.AddContext(&step.Context{
			Name:      name,
			Profile:   profile,
			Authority: authority,
		}); err != nil {
			return err
		}
		args = append(args, "--context", name)
	}
	if ctx.Bool("force") {
		args = append(args, "--force")
	}
	if ctx.Bool("install") {
		args = append(args, "--install")
	}
	if _, err := exec.Step(args...); err != nil {
		return errors.Wrap(err, "error getting authority data")
	}

	// Set ca-url and root certificate
	ctx.Set("ca-url", caURL)
	ctx.Set("fingerprint", fingerprint)
	ctx.Set("root", pki.GetRootCAPath())

	return nil
}

func getHost(caURL string) (string, error) {
	u, err := url.Parse(caURL)
	if err != nil {
		return "", err
	}
	host := u.Host
	if strings.Contains(host, ":") {
		if host, _, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}
	return host, nil
}

type apiError struct {
	StatusCode int    `json:"statusCode"`
	Err        string `json:"error"`
	Message    string `json:"message"`
}

func (e *apiError) Error() string {
	return e.Message
}

func readJSON(r io.ReadCloser, v interface{}) error {
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}

func readError(r io.ReadCloser) error {
	defer r.Close()
	apiErr := new(apiError)
	if err := json.NewDecoder(r).Decode(apiErr); err != nil {
		return err
	}
	return apiErr
}
