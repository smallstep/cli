package cautils

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/exec"
	"github.com/urfave/cli"

	"github.com/pkg/errors"
)

type bootstrapAPIResponse struct {
	CaURL       string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	RedirectURL string `json:"redirect-url"`
}

// BootstrapTeam does a request to api.smallstep.com to bootstrap the
// configuration of the given team ID (slug).
func BootstrapTeam(ctx *cli.Context, teamID string) error {
	apiEndpoint := ctx.String("team-url")
	if apiEndpoint == "" {
		// Use the default endpoint..
		u := url.URL{
			Scheme: "https",
			Host:   "api.smallstep.com",
			Path:   "/v1/teams/" + teamID + "/authorities/ssh",
		}
		apiEndpoint = u.String()
	} else {
		// The user specified a custom endpoint..
		apiEndpoint = strings.ReplaceAll(apiEndpoint, "<>", teamID)
		u, err := url.Parse(apiEndpoint)
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", apiEndpoint)
		}
		apiEndpoint = u.String()
	}

	// Using public PKI
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		return errors.Wrap(err, "error getting team data")
	}
	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusNotFound {
			return errors.New("error getting team data: team not found")
		}
		return errors.Wrap(readError(resp.Body), "error getting team data")
	}

	var r bootstrapAPIResponse
	if err := readJSON(resp.Body, &r); err != nil {
		return errors.Wrap(err, "error getting team data")
	}

	if r.RedirectURL == "" {
		r.RedirectURL = "https://smallstep.com/app/teams/sso/success"
	}

	args := []string{"ca", "bootstrap",
		"--ca-url", r.CaURL,
		"--fingerprint", r.Fingerprint,
		"--redirect-url", r.RedirectURL,
	}
	if ctx.Bool("force") {
		args = append(args, "--force")
	}
	if _, err := exec.Step(args...); err != nil {
		return errors.Wrap(err, "error getting team data")
	}

	// Set ca-url and root certificate
	ctx.Set("ca-url", r.CaURL)
	ctx.Set("fingerprint", r.Fingerprint)
	ctx.Set("root", pki.GetRootCAPath())

	return nil
}

// BootstrapAuthority does a request to api.smallstep.com to bootstrap the
// configuration of a given team/authority.
func BootstrapAuthority(ctx *cli.Context, teamID, authorityID string) error {
	apiEndpoint := ctx.String("team-url")
	if apiEndpoint == "" {
		// Use the default endpoint..
		u := url.URL{
			Scheme: "https",
			Host:   "api.smallstep.com",
			Path:   "/v1/teams/" + teamID + "/authorities/" + authorityID,
		}
		apiEndpoint = u.String()
	} else {
		// TODO FIX THIS!
		// The user specified a custom endpoint..
		apiEndpoint = strings.ReplaceAll(apiEndpoint, "<>", teamID)
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

	args := []string{"ca", "bootstrap",
		"--ca-url", r.CaURL,
		"--fingerprint", r.Fingerprint,
		"--redirect-url", r.RedirectURL,
	}
	/*
		if ctx.Bool("force") {
			args = append(args, "--force")
		}
	*/
	if _, err := exec.Step(args...); err != nil {
		return errors.Wrap(err, "error getting team data")
	}

	// Set ca-url and root certificate
	ctx.Set("ca-url", r.CaURL)
	ctx.Set("fingerprint", r.Fingerprint)
	ctx.Set("root", pki.GetRootCAPath())

	return nil
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
