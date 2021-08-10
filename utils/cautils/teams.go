package cautils

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/step"

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
func BootstrapAuthority(ctx *cli.Context, team, authority string) error {
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
		// TODO FIX THIS!
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

	args := []string{"ca", "bootstrap",
		"--ca-url", r.CaURL,
		"--fingerprint", r.Fingerprint,
		"--redirect-url", r.RedirectURL,
	}

	if ctx.IsSet("context-profile") {
		args = append(args, "--context-profile", ctx.String("context-profile"))
	} else {
		args = append(args, "--context-profile", team)
	}
	if ctx.IsSet("context-name") {
		args = append(args, "--context-name", ctx.String("context-name"))
	} else {
		args = append(args, "--context-name", authority)
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

// PrepareContext adds the context and sets up the profile.
func PrepareContext(ctx *cli.Context, caURL, name, profile string) error {
	u, err := url.Parse(caURL)
	if err != nil {
		return err
	}
	host := u.Host
	if strings.Contains(host, ":") {
		if host, _, err = net.SplitHostPort(host); err != nil {
			return err
		}
	}

	if name == "" {
		name = host
	}
	if profile == "" {
		profile = host
	}
	stepCtx := &step.Context{
		Name:      name,
		Authority: host,
		Profile:   profile,
	}

	if err := step.AddContext(stepCtx); err != nil {
		return err
	}
	if err := step.SwitchCurrentContext(stepCtx.Name); err != nil {
		return err
	}

	profileDefaultsFile := filepath.Join(step.ProfilePath(), "config", "defaults.json")

	if err := os.MkdirAll(filepath.Dir(profileDefaultsFile), 0700); err != nil {
		return errs.FileError(err, profileDefaultsFile)
	}

	if _, err := os.Stat(profileDefaultsFile); os.IsNotExist(err) {
		if err := ioutil.WriteFile(profileDefaultsFile, []byte("{}"), 0600); err != nil {
			return errs.FileError(err, profileDefaultsFile)
		}
		ui.Printf("The profile configuration has been saved in %s.\n", profileDefaultsFile)
	}

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
