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

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/truststore"
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

func useContext(ctx *cli.Context) bool {
	return step.Contexts().Enabled() ||
		ctx.IsSet("context") ||
		ctx.IsSet("authority") ||
		ctx.IsSet("profile")
}

type bootstrapOption func(bc *bootstrapContext)

type bootstrapContext struct {
	defaultContextName   string
	defaultAuthorityName string
	defaultProfileName   string
	redirectURL          string
}

func withDefaultContextValues(context, authority, profile string) bootstrapOption {
	return func(bc *bootstrapContext) {
		bc.defaultContextName = context
		bc.defaultAuthorityName = authority
		bc.defaultProfileName = profile
	}
}

func withRedirectURL(r string) bootstrapOption {
	return func(bc *bootstrapContext) {
		bc.redirectURL = r
	}
}

type bootstrapConfig struct {
	CA          string `json:"ca-url"`
	Fingerprint string `json:"fingerprint"`
	Root        string `json:"root"`
	Redirect    string `json:"redirect-url"`
}

func bootstrap(ctx *cli.Context, caURL, fingerprint string, opts ...bootstrapOption) error {
	bc := new(bootstrapContext)
	for _, o := range opts {
		o(bc)
	}

	if useContext(ctx) {
		authority := ctx.String("authority")
		if authority == "" {
			authority = bc.defaultAuthorityName
		}
		context := ctx.String("context")
		if context == "" {
			context = bc.defaultContextName
		}
		profile := ctx.String("profile")
		if profile == "" {
			profile = bc.defaultProfileName
		}
		if err := step.Contexts().Add(&step.Context{
			Name:      context,
			Profile:   profile,
			Authority: authority,
		}); err != nil {
			return errors.Wrapf(err, "error adding context: '%s' - {authority: '%s', profile: '%s'}",
				context, authority, profile)
		}
		if err := step.Contexts().SaveCurrent(context); err != nil {
			return errors.Wrap(err, "error storing new default context")
		}
		if err := step.Contexts().SetCurrent(context); err != nil {
			return errors.Wrap(err, "error setting context '%s'")
		}
	}

	tr := utils.GetInsecureTransport()
	client, err := ca.NewClient(caURL, ca.WithTransport(tr))
	if err != nil {
		return err
	}

	// Root already validates the certificate
	resp, err := client.Root(fingerprint)
	if err != nil {
		return errors.Wrap(err, "error downloading root certificate")
	}

	rootFile := pki.GetRootCAPath()
	configFile := step.DefaultsFile()

	if err = os.MkdirAll(filepath.Dir(rootFile), 0700); err != nil {
		return errs.FileError(err, rootFile)
	}

	if err = os.MkdirAll(filepath.Dir(configFile), 0700); err != nil {
		return errs.FileError(err, configFile)
	}

	// Serialize root
	_, err = pemutil.Serialize(resp.RootPEM.Certificate, pemutil.ToFile(rootFile, 0600))
	if err != nil {
		return err
	}
	ui.Printf("The root certificate has been saved in %s.\n", rootFile)

	// make sure to store the url with https
	caURL, err = utils.CompleteURL(caURL)
	if err != nil {
		return err
	}

	// Serialize defaults.json
	b, err := json.MarshalIndent(bootstrapConfig{
		CA:          caURL,
		Fingerprint: fingerprint,
		Root:        pki.GetRootCAPath(),
		Redirect:    bc.redirectURL,
	}, "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling defaults.json")
	}

	if err := utils.WriteFile(configFile, b, 0644); err != nil {
		return err
	}

	ui.Printf("The authority configuration has been saved in %s.\n", configFile)

	if step.Contexts().Enabled() {
		profileDefaultsFile := step.ProfileDefaultsFile()

		if err := os.MkdirAll(filepath.Dir(profileDefaultsFile), 0700); err != nil {
			return errs.FileError(err, profileDefaultsFile)
		}

		if _, err := os.Stat(profileDefaultsFile); os.IsNotExist(err) {
			if err := ioutil.WriteFile(profileDefaultsFile, []byte("{}"), 0600); err != nil {
				return errs.FileError(err, profileDefaultsFile)
			}
			ui.Printf("The profile configuration has been saved in %s.\n", profileDefaultsFile)
		}
	}

	if ctx.Bool("install") {
		ui.Printf("Installing the root certificate in the system truststore... ")
		if err := truststore.InstallFile(rootFile); err != nil {
			ui.Println()
			return err
		}
		ui.Println("done.")
	}

	return nil
}

// BootstrapTeamAuthority does a request to api.smallstep.com to bootstrap the
// configuration of a given team/authority.
func BootstrapTeamAuthority(ctx *cli.Context, team, teamAuthority string) error {
	apiEndpoint := ctx.String("team-url")
	if apiEndpoint == "" {
		// Use the default endpoint..
		u := url.URL{
			Scheme: "https",
			Host:   "api.smallstep.com",
			Path:   "/v1/teams/" + team + "/authorities/" + teamAuthority,
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

	caHostname, err := getHost(r.CaURL)
	if err != nil {
		return err
	}
	return bootstrap(ctx, r.CaURL, r.Fingerprint,
		withDefaultContextValues(teamAuthority+"."+team, caHostname, team),
		withRedirectURL(r.RedirectURL))
}

// BootstrapAuthority bootstraps an autority using only the caURL and fingerprint.
func BootstrapAuthority(ctx *cli.Context, caURL, fingerprint string) (err error) {
	caHostname := ctx.String("authority")
	if caHostname == "" {
		if caHostname, err = getHost(caHostname); err != nil {
			return err
		}
	}
	return bootstrap(ctx, caURL, fingerprint,
		withDefaultContextValues(caHostname, caHostname, caHostname))
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
