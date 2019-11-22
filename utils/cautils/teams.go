package cautils

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/exec"
	"github.com/urfave/cli"

	"github.com/pkg/errors"
)

const apiEndpoint = "https://api.smallstep.com"

type bootstrapAPIResponse struct {
	CaURL       string `json:"url"`
	Fingerprint string `json:"fingerprint"`
}

// BootstrapTeam does a request to api.smallstep.com to bootstrap the
// configuration of the given team name.
func BootstrapTeam(ctx *cli.Context, name string) error {
	u, err := url.Parse(apiEndpoint)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", apiEndpoint)
	}
	u = u.ResolveReference(&url.URL{
		Path: "/v1/teams/" + name + "/cas/default",
	})

	// Using public PKI
	resp, err := http.Get(u.String())
	if err != nil {
		return errors.Wrap(err, "error getting team data")
	}
	if resp.StatusCode >= 400 {
		return errors.Wrap(readError(resp.Body), "error getting team data")
	}

	var r bootstrapAPIResponse
	if err := readJSON(resp.Body, &r); err != nil {
		return errors.Wrap(err, "error getting team data")
	}

	args := []string{"ca", "bootstrap",
		"--ca-url", r.CaURL,
		"--fingerprint", r.Fingerprint,
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
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return err
	}
	return nil
}

func readError(r io.ReadCloser) error {
	defer r.Close()
	apiErr := new(apiError)
	if err := json.NewDecoder(r).Decode(apiErr); err != nil {
		return err
	}
	return apiErr
}
