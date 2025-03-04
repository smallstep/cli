package cautils

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/step"
	"github.com/smallstep/cli-utils/ui"
	"github.com/smallstep/truststore"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/utils"
)

type bootstrapAPIResponse struct {
	CaURL             string `json:"url"`
	Fingerprint       string `json:"fingerprint"`
	RedirectURL       string `json:"redirect-url"`
	Provisioner       string `json:"provisioner"`
	MinPasswordLength int    `json:"min-password-length"`
}

// UseContext returns true if contexts should be used, false otherwise.
func UseContext(ctx *cli.Context) (ret bool) {
	return step.Contexts().Enabled() ||
		ctx.IsSet("context") ||
		ctx.IsSet("authority") ||
		ctx.IsSet("profile")
}

// WarnContext outputs a warning informing users about the option to use
// contexts.
func WarnContext() {
	// If not using contexts but an existing CA has already been configured,
	// advise the user to use contexts in the future.
	if _, err := os.Stat(filepath.Join(step.BasePath(), "config", "ca.json")); err == nil {
		ui.Println("⚠️  It looks like step is already configured to connect to an authority.\n" +
			"You can use 'contexts' to easily switch between teams and authorities.\n" +
			"Learn more at https://smallstep.com/docs/step-cli/the-step-command#contexts.\n")
	}
}

type bootstrapOption func(bc *bootstrapContext)

type bootstrapContext struct {
	defaultContextName string
	redirectURL        string
	provisioner        string
	minPasswordLength  int
}

func withProvisioner(provisioner string) bootstrapOption {
	return func(bc *bootstrapContext) {
		bc.provisioner = provisioner
	}
}

func withMinPasswordLength(minLength int) bootstrapOption {
	return func(bc *bootstrapContext) {
		bc.minPasswordLength = minLength
	}
}

func withDefaultContextValues(context string) bootstrapOption {
	return func(bc *bootstrapContext) {
		bc.defaultContextName = context
	}
}

func withRedirectURL(r string) bootstrapOption {
	return func(bc *bootstrapContext) {
		bc.redirectURL = r
	}
}

type bootstrapConfig struct {
	CA                string `json:"ca-url"`
	Fingerprint       string `json:"fingerprint"`
	Root              string `json:"root"`
	Redirect          string `json:"redirect-url,omitempty"`
	Provisioner       string `json:"provisioner,omitempty"`
	MinPasswordLength int    `json:"min-password-length,omitempty"`
}

func bootstrap(ctx *cli.Context, caURL, fingerprint string, opts ...bootstrapOption) error {
	bc := new(bootstrapContext)
	for _, o := range opts {
		o(bc)
	}

	client, err := ca.NewClient(caURL, ca.WithInsecure())
	if err != nil {
		return err
	}

	// Root already validates the certificate
	resp, err := client.Root(fingerprint)
	if err != nil {
		return errors.Wrap(err, "error downloading root certificate")
	}

	if UseContext(ctx) {
		ctxName := ctx.String("context")
		if ctxName == "" {
			ctxName = bc.defaultContextName
		}
		ctxAuthority := ctx.String("authority")
		if ctxAuthority == "" {
			ctxAuthority = ctxName
		}
		ctxProfile := ctx.String("profile")
		if ctxProfile == "" {
			ctxProfile = ctxName
		}
		if err := step.Contexts().Add(&step.Context{
			Name:      ctxName,
			Profile:   ctxProfile,
			Authority: ctxAuthority,
		}); err != nil {
			return errors.Wrapf(err, "error adding context: '%s' - {authority: '%s', profile: '%s'}",
				ctxName, ctxAuthority, ctxProfile)
		}
		if err := step.Contexts().SaveCurrent(ctxName); err != nil {
			return errors.Wrap(err, "error storing new default context")
		}
		if err := step.Contexts().SetCurrent(ctxName); err != nil {
			return errors.Wrap(err, "error setting context '%s'")
		}
	} else {
		WarnContext()
	}
	rootFile := pki.GetRootCAPath()
	configFile := step.DefaultsFile()

	if err = os.MkdirAll(filepath.Dir(rootFile), 0o700); err != nil {
		return errs.FileError(err, rootFile)
	}

	if err = os.MkdirAll(filepath.Dir(configFile), 0o700); err != nil {
		return errs.FileError(err, configFile)
	}

	// Serialize root
	_, err = pemutil.Serialize(resp.RootPEM.Certificate, pemutil.ToFile(rootFile, 0o600))
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
	bootConf := bootstrapConfig{
		CA:          caURL,
		Fingerprint: fingerprint,
		Root:        pki.GetRootCAPath(),
		Redirect:    bc.redirectURL,
	}
	if bc.minPasswordLength > 0 {
		bootConf.MinPasswordLength = bc.minPasswordLength
	}
	if bc.provisioner != "" {
		bootConf.Provisioner = bc.provisioner
	}
	b, err := json.MarshalIndent(bootConf, "", "  ")
	if err != nil {
		return errors.Wrap(err, "error marshaling defaults.json")
	}

	ctx.Set("ca-url", caURL)
	ctx.Set("fingerprint", fingerprint)
	ctx.Set("root", rootFile)

	if err := utils.WriteFile(configFile, b, 0o644); err != nil {
		return err
	}

	ui.Printf("The authority configuration has been saved in %s.\n", configFile)

	if step.Contexts().Enabled() {
		profileDefaultsFile := step.ProfileDefaultsFile()

		if err := os.MkdirAll(filepath.Dir(profileDefaultsFile), 0o700); err != nil {
			return errs.FileError(err, profileDefaultsFile)
		}

		if _, err := os.Stat(profileDefaultsFile); os.IsNotExist(err) {
			if err := os.WriteFile(profileDefaultsFile, []byte("{}"), 0o600); err != nil {
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
		// TODO implement support for replacing the authority section of the
		// URL with placeholders as well.
		apiEndpoint = strings.ReplaceAll(apiEndpoint, "<>", team)
		u, err := url.Parse(apiEndpoint)
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", apiEndpoint)
		}
		apiEndpoint = u.String()
	}

	// Get the --redirect-url flag, If passed, we will use this one even if the
	// API provides one.
	redirectURL := ctx.String("redirect-url")
	if redirectURL != "" {
		if _, err := url.Parse(redirectURL); err != nil {
			return err
		}
	}

	// Using public PKI
	//nolint:gosec // Variadic URL is considered safe here for the following reasons:
	//  1) The input is from the command line, rather than a web form or publicly available API.
	//  2) The command is expected to be used on a client, rather than a privileged backend host.
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		return errors.Wrap(err, "error getting authority data")
	}
	defer resp.Body.Close()
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
	if redirectURL != "" {
		r.RedirectURL = redirectURL
	} else if r.RedirectURL == "" {
		r.RedirectURL = "https://smallstep.com/app/teams/sso/success"
	}

	bootOpts := []bootstrapOption{
		withDefaultContextValues(teamAuthority + "." + team),
		withRedirectURL(r.RedirectURL),
	}
	if r.Provisioner != "" {
		bootOpts = append(bootOpts, withProvisioner(r.Provisioner))
	}
	if r.MinPasswordLength > 0 {
		bootOpts = append(bootOpts, withMinPasswordLength(r.MinPasswordLength))
	}
	return bootstrap(ctx, r.CaURL, r.Fingerprint, bootOpts...)
}

// BootstrapAuthority bootstraps an authority using only the caURL and fingerprint.
func BootstrapAuthority(ctx *cli.Context, caURL, fingerprint string) (err error) {
	caHostname := ctx.String("authority")
	if caHostname == "" {
		if caHostname, err = getHost(caURL); err != nil {
			return err
		}
	}

	opts := []bootstrapOption{
		withDefaultContextValues(caHostname),
	}

	if redirectURL := ctx.String("redirect-url"); redirectURL != "" {
		if _, err := url.Parse(redirectURL); err != nil {
			return err
		}
		opts = append(opts, withRedirectURL(redirectURL))
	}

	return bootstrap(ctx, caURL, fingerprint, opts...)
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
