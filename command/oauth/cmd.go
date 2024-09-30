package oauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

// These are the OAuth2.0 client IDs from the Step CLI. This application is
// using the OAuth2.0 flow for installed applications described on
// https://developers.google.com/identity/protocols/OAuth2InstalledApp
//
// The Step CLI app and these client IDs do not have any APIs or services are
// enabled and it should be only used for OAuth 2.0 authorization.
//
// Due to the fact that the app cannot keep the client_secret confidential,
// incremental authorization with installed apps are not supported by Google.
//
// Google is also distributing the client ID and secret on the cloud SDK
// available here https://cloud.google.com/sdk/docs/quickstarts
const (
	//nolint:gosec // This is a client meant for open source testing. The client has no security access or roles.
	defaultClientID = "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com"
	//nolint:gosec // This is a client meant for open source testing. The client has no security access or roles.
	defaultClientNotSoSecret = "udTrOT3gzrO7W9fDPgZQLfYJ"

	//nolint:gosec // This is a client meant for open source testing. The client has no security access or roles.
	defaultDeviceAuthzClientID = "1087160488420-1u0jqoulmv3mfomfh6fhkfs4vk4bdjih.apps.googleusercontent.com"
	//nolint:gosec // This is a client meant for open source testing. The client has no security access or roles.
	defaultDeviceAuthzClientNotSoSecret = "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"

	defaultDeviceAuthzInterval  = 5
	defaultDeviceAuthzExpiresIn = time.Minute * 5

	// The URN for getting verification token offline
	oobCallbackUrn = "urn:ietf:wg:oauth:2.0:oob"
	// The URN for token request grant type jwt-bearer
	//nolint:gosec // This is a resource identifier (not a secret).
	jwtBearerUrn = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type token struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Err          string `json:"error,omitempty"`
	ErrDesc      string `json:"error_description,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func init() {
	cmd := cli.Command{
		Name:  "oauth",
		Usage: "authorization and single sign-on using OAuth & OIDC",
		UsageText: `**step oauth**
[**--provider**=<provider>] [**--client-id**=<client-id> **--client-secret**=<client-secret>]
[**--scope**=<scope> ...] [**--bare** [**--oidc**]] [**--header** [**--oidc**]]
[**--prompt**=<prompt>] [**--auth-param**=<key=value>]

**step oauth**
**--authorization-endpoint**=<authorization-endpoint>
**--token-endpoint**=<token-endpoint>
**--client-id**=<client-id> **--client-secret**=<client-secret>
[**--scope**=<scope> ...] [**--bare** [**--oidc**]] [**--header** [**--oidc**]]
[**--prompt**=<prompt>] [**--auth-param**=<key=value>]

**step oauth** [**--account**=<account>]
[**--authorization-endpoint**=<authorization-endpoint>]
[**--token-endpoint**=<token-endpoint>]
[**--scope**=<scope> ...] [**--bare** [**--oidc**]] [**--header** [**--oidc**]]
[**--prompt**=<prompt>] [**--auth-param**=<key=value>]

**step oauth** **--account**=<account> **--jwt**
[**--scope**=<scope> ...] [**--header**] [**-bare**] [**--prompt**=<prompt>]
[**--auth-param**=<key=value>]`,
		Description: `**step oauth** command implements the OAuth 2.0 authorization flow.

OAuth is an open standard for access delegation, commonly used as a way for
Internet users to grant websites or applications access to their information on
other websites but without giving them the passwords. This mechanism is used by
companies such as Amazon, Google, Facebook, Microsoft and Twitter to permit the
users to share information about their accounts with third party applications or
websites. Learn more at https://en.wikipedia.org/wiki/OAuth.

This command by default performs the authorization flow with a preconfigured
Google application, but a custom one can be set combining the flags
**--client-id**, **--client-secret**, and **--provider**. The provider value
must be set to the OIDC discovery document (.well-known/openid-configuration)
endpoint. If Google is used this flag is not necessary, but the appropriate
value would be be https://accounts.google.com or
https://accounts.google.com/.well-known/openid-configuration

## EXAMPLES

Do the OAuth 2.0 flow using the default client:
'''
$ step oauth
'''

Redirect to localhost instead of 127.0.0.1:
'''
$ step oauth --listen localhost:0
'''

Redirect to a fixed port instead of random one:
'''
$ step oauth --listen :10000
'''

Redirect to a fixed url but listen on all the interfaces:
'''
$ step oauth --listen 0.0.0.0:10000 --listen-url http://127.0.0.1:10000
'''

Get just the access token:
'''
$ step oauth --bare
'''

Get just the OIDC token:
'''
$ step oauth --oidc --bare
'''

Use a custom OAuth2.0 server:
'''
$ step oauth --client-id my-client-id --client-secret my-client-secret \
  --provider https://example.org
'''

Use the Device Authorization Grant flow for input constrained clients:
'''
$ step oauth --client-id my-client-id --client-secret my-client-secret --console-flow device
'''

Use the Out Of Band flow for input constrained clients:
'''
$ step oauth --client-id my-client-id --client-secret my-client-secret --console-flow oob
'''

Use the default OAuth flow for input constrained clients:
'''
$ step oauth --client-id my-client-id --client-secret my-client-secret --console
'''

Use additional authentication parameters:
'''
$ step oauth --client-id my-client-id --client-secret my-client-secret \
  --provider https://example.org --auth-param "access_type=offline"
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "provider, idp",
				Usage: "OAuth provider for authentication",
				Value: "google",
			},
			cli.StringFlag{
				Name:  "email, e",
				Usage: "Email to authenticate",
			},
			cli.BoolFlag{
				Name: "console, c",
				Usage: `Complete the flow while remaining only inside the terminal.
This flag defaults to use the Device Authorization Grant flow.`,
			},
			cli.StringFlag{
				Name: "console-flow",
				Usage: `The alternative OAuth <flow> to use for input constrained devices.

: <console-flow> is a case-insensitive string and must be one of:

    **device**
    :  Use the Device Authorization Grant (https://datatracker.ietf.org/doc/html/rfc8628#section-3.2) flow

    **oob**
    :  Use the Out of Band (OOB) flow`,
			},
			cli.StringFlag{
				Name:  "client-id",
				Usage: "OAuth Client ID",
			},
			cli.StringFlag{
				Name:  "client-secret",
				Usage: "OAuth Client Secret",
			},
			cli.StringFlag{
				Name:  "account",
				Usage: "JSON file containing account details",
			},
			cli.StringFlag{
				Name:  "authorization-endpoint",
				Usage: "OAuth Authorization Endpoint",
			},
			cli.StringFlag{
				Name:  "device-authorization-endpoint",
				Usage: "OAuth Device Authorization Endpoint",
			},
			cli.StringFlag{
				Name:  "token-endpoint",
				Usage: "OAuth Token Endpoint",
			},
			cli.BoolFlag{
				Name:  "header",
				Usage: "Output HTTP Authorization Header (suitable for use with curl)",
			},
			cli.BoolFlag{
				Name:  "oidc",
				Usage: "Output OIDC Token instead of OAuth Access Token",
			},
			cli.BoolFlag{
				Name:  "bare",
				Usage: "Only output the token",
			},
			cli.StringSliceFlag{
				Name:  "scope",
				Usage: "OAuth scopes",
			},
			cli.StringSliceFlag{
				Name: "auth-param",
				Usage: `OAuth additional authentication parameters to include as part of the URL query.
Use this flag multiple times to add multiple parameters. This flag expects a
'key' and 'value' in the format '--auth-param "key=value"'.`,
			},
			cli.StringFlag{
				Name: "prompt",
				Usage: `Whether the Authorization Server prompts the End-User for reauthentication and consent.
OpenID standard defines the following values, but your provider may support some or none of them:

    **none**
    :   The Authorization Server MUST NOT display any authentication or consent user interface pages.
        An error is returned if an End-User is not already authenticated or the Client does not have
        pre-configured consent for the requested Claims or does not fulfill other conditions for
        processing the request.

    **login**
    :   The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot
        reauthenticate the End-User, it MUST return an error, typically login_required.

    **consent**
    :   The Authorization Server SHOULD prompt the End-User for consent before returning information
        to the Client. If it cannot obtain consent, it MUST return an error, typically consent_required.

    **select_account**
    :   The Authorization Server SHOULD prompt the End-User to select a user account. This enables an
        End-User who has multiple accounts at the Authorization Server to select amongst the multiple
        accounts that they might have current sessions for. If it cannot obtain an account selection
        choice made by the End-User, it MUST return an error, typically account_selection_required.
`,
			},
			cli.BoolFlag{
				Name:  "jwt",
				Usage: "Generate a JWT Auth token instead of an OAuth Token (only works with service accounts)",
			},
			cli.StringFlag{
				Name:  "listen",
				Usage: "Callback listener <address> (e.g. \":10000\")",
			},
			cli.StringFlag{
				Name:  "listen-url",
				Usage: "The redirect_uri <url> in the authorize request (e.g. \"http://127.0.0.1:10000\")",
			},
			cli.BoolFlag{
				Name:   "implicit",
				Usage:  "Uses the implicit flow to authenticate the user. Requires **--insecure** and **--client-id** flags.",
				Hidden: true,
			},
			cli.StringFlag{
				Name:   "browser",
				Usage:  "Path to browser for OAuth flow (macOS only).",
				Hidden: true,
			},
			flags.RedirectURL,
			flags.InsecureHidden,
		},
		Action: oauthCmd,
	}

	command.Register(cmd)
}

type consoleFlow int

const (
	oobConsoleFlow consoleFlow = iota
	deviceConsoleFlow
)

type options struct {
	Provider            string
	Email               string
	Console             bool
	ConsoleFlow         consoleFlow
	Implicit            bool
	CallbackListener    string
	CallbackListenerURL string
	CallbackPath        string
	TerminalRedirect    string
	Browser             string
}

// Validate validates the options.
func (o *options) Validate() error {
	if o.Provider != "google" && o.Provider != "github" && !strings.HasPrefix(o.Provider, "https://") {
		return errors.New("use a valid provider: google or github")
	}
	if o.CallbackListener != "" {
		if _, _, err := net.SplitHostPort(o.CallbackListener); err != nil {
			return errors.Wrapf(err, "invalid value '%s' for flag '--listen'", o.CallbackListener)
		}
	}
	if o.CallbackListenerURL != "" {
		u, err := url.Parse(o.CallbackListenerURL)
		if err != nil || u.Scheme == "" {
			return errors.Wrapf(err, "invalid value '%s' for flag '--listen-url'", o.CallbackListenerURL)
		}
		if u.Path != "" {
			o.CallbackPath = u.Path
		}
	}
	return nil
}

func oauthCmd(c *cli.Context) error {
	opts := &options{
		Provider:            c.String("provider"),
		Email:               c.String("email"),
		Console:             c.Bool("console"),
		Implicit:            c.Bool("implicit"),
		CallbackListener:    c.String("listen"),
		CallbackListenerURL: c.String("listen-url"),
		CallbackPath:        "/",
		TerminalRedirect:    c.String("redirect-url"),
		Browser:             c.String("browser"),
	}
	if err := opts.Validate(); err != nil {
		return err
	}
	if (opts.Provider != "google" || c.IsSet("authorization-endpoint")) && !c.IsSet("client-id") {
		return errors.New("flag '--client-id' required with '--provider'")
	}

	isOOBFlow, isDeviceFlow := false, false
	consoleFlowInput := c.String("console-flow")
	switch {
	case strings.EqualFold(consoleFlowInput, "device"):
		opts.Console = true
		opts.ConsoleFlow = deviceConsoleFlow
		isDeviceFlow = true
	case strings.EqualFold(consoleFlowInput, "oob"):
		opts.Console = true
		opts.ConsoleFlow = oobConsoleFlow
		isOOBFlow = true
	case c.IsSet("console-flow"):
		return errs.InvalidFlagValue(c, "console-flow", consoleFlowInput, "device, oob")
	case c.Bool("console"):
		isDeviceFlow = true
		opts.ConsoleFlow = deviceConsoleFlow
	}

	var clientID, clientSecret string
	switch {
	case opts.Implicit:
		if !c.Bool("insecure") {
			return errs.RequiredInsecureFlag(c, "implicit")
		}
		if !c.IsSet("client-id") {
			return errs.RequiredWithFlag(c, "implicit", "client-id")
		}
	case isDeviceFlow:
		clientID = defaultDeviceAuthzClientID
		clientSecret = defaultDeviceAuthzClientNotSoSecret
	default:
		clientID = defaultClientID
		clientSecret = defaultClientNotSoSecret
	}

	if c.IsSet("client-id") {
		clientID = c.String("client-id")
		clientSecret = c.String("client-secret")
	}

	authzEp := ""
	deviceAuthzEp := ""
	tokenEp := ""
	if c.IsSet("authorization-endpoint") {
		if !c.IsSet("token-endpoint") {
			return errors.New("flag '--authorization-endpoint' requires flag '--token-endpoint'")
		}
		opts.Provider = ""
		authzEp = c.String("authorization-endpoint")
		tokenEp = c.String("token-endpoint")
	}
	if c.IsSet("device-authorization-endpoint") {
		if !c.IsSet("token-endpoint") {
			return errors.New("flag '--device-authorization-endpoint' requires flag '--token-endpoint'")
		}
		opts.Provider = ""
		deviceAuthzEp = c.String("device-authorization-endpoint")
		tokenEp = c.String("token-endpoint")
	}

	do2lo := false
	issuer := ""
	// This code supports Google service accounts. Probably maybe also support JWKs?
	if c.IsSet("account") {
		opts.Provider = ""
		filename := c.String("account")
		b, err := os.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading account from %s", filename)
		}
		account := make(map[string]interface{})
		if err = json.Unmarshal(b, &account); err != nil {
			return errors.Wrapf(err, "error reading %s: unsupported format", filename)
		}

		if _, ok := account["installed"]; ok {
			details := account["installed"].(map[string]interface{})
			authzEp = details["auth_uri"].(string)
			tokenEp = details["token_uri"].(string)
			clientID = details["client_id"].(string)
			clientSecret = details["client_secret"].(string)
		} else if accountType, ok := account["type"]; ok && accountType == "service_account" {
			authzEp = account["auth_uri"].(string)
			tokenEp = account["token_uri"].(string)
			clientID = account["private_key_id"].(string)
			clientSecret = account["private_key"].(string)
			issuer = account["client_email"].(string)
			do2lo = true
		} else {
			return errors.Wrapf(err, "error reading %s: unsupported account type", filename)
		}
	}

	scope := "openid email"
	if c.IsSet("scope") {
		scope = strings.Join(c.StringSlice("scope"), " ")
	}
	prompt := ""
	if c.IsSet("prompt") {
		prompt = c.String("prompt")
	}

	authParams := url.Values{}
	for _, keyval := range c.StringSlice("auth-param") {
		parts := strings.SplitN(keyval, "=", 2)
		var k, v string
		switch len(parts) {
		case 1:
			k, v = parts[0], ""
		case 2:
			k, v = parts[0], parts[1]
		default:
			return errs.InvalidFlagValue(c, "auth-param", keyval, "")
		}
		if k == "" {
			return errs.InvalidFlagValue(c, "auth-param", keyval, "")
		}
		authParams.Add(k, v)
	}

	o, err := newOauth(opts.Provider, clientID, clientSecret, authzEp, deviceAuthzEp, tokenEp, scope, prompt, authParams, opts)
	if err != nil {
		return err
	}

	var tok *token
	switch {
	case do2lo:
		if c.Bool("jwt") {
			tok, err = o.DoJWTAuthorization(issuer, scope)
		} else {
			tok, err = o.DoTwoLeggedAuthorization(issuer)
		}
	case isDeviceFlow:
		tok, err = o.DoDeviceAuthorization()
	case isOOBFlow:
		tok, err = o.DoManualAuthorization()
	default:
		tok, err = o.DoLoopbackAuthorization()
	}

	if err != nil {
		return err
	}

	if c.Bool("header") {
		if c.Bool("oidc") {
			fmt.Println("Authorization: Bearer", tok.IDToken)
		} else {
			fmt.Println("Authorization: Bearer", tok.AccessToken)
		}
	} else {
		if c.Bool("bare") {
			if c.Bool("oidc") {
				fmt.Println(tok.IDToken)
			} else {
				fmt.Println(tok.AccessToken)
			}
		} else {
			b, err := json.MarshalIndent(tok, "", "  ")
			if err != nil {
				return errors.Wrapf(err, "error marshaling token data")
			}
			fmt.Println(string(b))
		}
	}

	return nil
}

type oauth struct {
	provider            string
	clientID            string
	clientSecret        string
	scope               string
	prompt              string
	loginHint           string
	redirectURI         string
	tokenEndpoint       string
	authzEndpoint       string
	deviceAuthzEndpoint string
	userInfoEndpoint    string // For testing
	state               string
	codeChallenge       string
	nonce               string
	implicit            bool
	CallbackListener    string
	CallbackListenerURL string
	CallbackPath        string
	terminalRedirect    string
	browser             string
	authParams          url.Values
	errCh               chan error
	tokCh               chan *token
}

type endpoint struct {
	authorization       string
	deviceAuthorization string
	token               string
	userInfo            string
}

var knownProviders = map[string]endpoint{
	"google": {
		authorization:       "https://accounts.google.com/o/oauth2/v2/auth",
		deviceAuthorization: "https://oauth2.googleapis.com/device/code",
		token:               "https://www.googleapis.com/oauth2/v4/token",
		userInfo:            "https://www.googleapis.com/oauth2/v3/userinfo",
	},
	"github": {
		authorization:       "https://github.com/login/oauth/authorize",
		deviceAuthorization: "https://github.com/login/device/code",
		token:               "https://github.com/login/oauth/access_token",
		userInfo:            "https://api.github.com/user",
	},
}

func newOauth(provider, clientID, clientSecret, authzEp, deviceAuthzEp, tokenEp, scope, prompt string, authParams url.Values, opts *options) (*oauth, error) {
	state, err := randutil.Alphanumeric(32)
	if err != nil {
		return nil, err
	}

	challenge, err := randutil.Alphanumeric(64)
	if err != nil {
		return nil, err
	}

	nonce, err := randutil.Hex(64) // 256 bits
	if err != nil {
		return nil, err
	}

	// Check known providers
	if p, ok := knownProviders[provider]; ok {
		return &oauth{
			provider:            provider,
			clientID:            clientID,
			clientSecret:        clientSecret,
			scope:               scope,
			prompt:              prompt,
			authzEndpoint:       p.authorization,
			deviceAuthzEndpoint: p.deviceAuthorization,
			tokenEndpoint:       p.token,
			userInfoEndpoint:    p.userInfo,
			loginHint:           opts.Email,
			state:               state,
			codeChallenge:       challenge,
			nonce:               nonce,
			implicit:            opts.Implicit,
			CallbackListener:    opts.CallbackListener,
			CallbackListenerURL: opts.CallbackListenerURL,
			CallbackPath:        opts.CallbackPath,
			terminalRedirect:    opts.TerminalRedirect,
			browser:             opts.Browser,
			authParams:          authParams,
			errCh:               make(chan error),
			tokCh:               make(chan *token),
		}, nil
	}

	userinfoEp := ""
	isDeviceFlow := opts.Console && opts.ConsoleFlow == deviceConsoleFlow

	if (isDeviceFlow && deviceAuthzEp == "" && tokenEp == "") || (!isDeviceFlow && authzEp == "" && tokenEp == "") {
		d, err := disco(provider)
		if err != nil {
			return nil, err
		}

		if v, ok := d["device_authorization_endpoint"].(string); !ok && isDeviceFlow {
			return nil, errors.New("missing or invalid 'device_authorization_endpoint' in provider metadata")
		} else if ok {
			deviceAuthzEp = v
		}
		if v, ok := d["authorization_endpoint"].(string); !ok && !isDeviceFlow {
			return nil, errors.New("missing or invalid 'authorization_endpoint' in provider metadata")
		} else if ok {
			authzEp = v
		}
		v, ok := d["token_endpoint"].(string)
		if !ok {
			return nil, errors.New("missing or invalid 'token_endpoint' in provider metadata")
		}
		tokenEp, userinfoEp = v, v
	}

	return &oauth{
		provider:            provider,
		clientID:            clientID,
		clientSecret:        clientSecret,
		scope:               scope,
		prompt:              prompt,
		authzEndpoint:       authzEp,
		deviceAuthzEndpoint: deviceAuthzEp,
		tokenEndpoint:       tokenEp,
		userInfoEndpoint:    userinfoEp,
		loginHint:           opts.Email,
		state:               state,
		codeChallenge:       challenge,
		nonce:               nonce,
		implicit:            opts.Implicit,
		CallbackListener:    opts.CallbackListener,
		CallbackListenerURL: opts.CallbackListenerURL,
		CallbackPath:        opts.CallbackPath,
		terminalRedirect:    opts.TerminalRedirect,
		browser:             opts.Browser,
		authParams:          authParams,
		errCh:               make(chan error),
		tokCh:               make(chan *token),
	}, nil
}

func disco(provider string) (map[string]interface{}, error) {
	u, err := url.Parse(provider)
	if err != nil {
		return nil, err
	}
	// TODO: OIDC and OAuth specify two different ways of constructing this
	// URL. This is the OIDC way. Probably want to try both. See
	// https://tools.ietf.org/html/rfc8414#section-5
	if !strings.Contains(u.Path, "/.well-known/openid-configuration") {
		u.Path = path.Join(u.Path, "/.well-known/openid-configuration")
	}
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving %s", u.String())
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving %s", u.String())
	}
	details := make(map[string]interface{})
	if err = json.Unmarshal(b, &details); err != nil {
		return nil, errors.Wrapf(err, "error reading %s: unsupported format", u.String())
	}
	return details, err
}

// postForm simulates http.PostForm but adds the header "Accept:
// application/json", without this header GitHub will use
// application/x-www-form-urlencoded.
func postForm(rawurl string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", rawurl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create POST %s request failed: %w", rawurl, err)
	}

	// Prevents re-use of TCP connections between requests.
	req.Close = true

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return http.DefaultClient.Do(req)
}

// NewServer creates http server
func (o *oauth) NewServer() (*httptest.Server, error) {
	if o.CallbackListener == "" {
		return httptest.NewServer(o), nil
	}
	host, port, err := net.SplitHostPort(o.CallbackListener)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, errors.Wrapf(err, "error listening on %s", o.CallbackListener)
	}
	srv := &httptest.Server{
		Listener: l,
		Config: &http.Server{
			Handler:           o,
			ReadHeaderTimeout: 15 * time.Second,
		},
	}
	srv.Start()

	// Update server url to use for example http://localhost:port
	if host != "127.0.0.1" {
		_, p, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %s", l.Addr().String())
		}
		srv.URL = "http://" + host + ":" + p
	}

	return srv, nil
}

// DoLoopbackAuthorization performs the log in into the identity provider
// opening a browser and using a redirect_uri in a loopback IP address
// (http://127.0.0.1:port or http://[::1]:port).
func (o *oauth) DoLoopbackAuthorization() (*token, error) {
	srv, err := o.NewServer()
	if err != nil {
		return nil, err
	}
	// Update server url if --listen-url is set
	if o.CallbackListenerURL != "" {
		o.redirectURI = o.CallbackListenerURL
	} else {
		o.redirectURI = srv.URL
	}
	defer srv.Close()

	// Get auth url and open it in a browser
	authURL, err := o.Auth()
	if err != nil {
		return nil, err
	}

	if err := exec.OpenInBrowser(authURL, o.browser); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open a web browser on your platform.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Open a local web browser and visit:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, authURL)
		fmt.Fprintln(os.Stderr)
	} else {
		fmt.Fprintln(os.Stderr, "Your default web browser has been opened to visit:")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, authURL)
		fmt.Fprintln(os.Stderr)
	}

	// Wait for response and return the token
	select {
	case tok := <-o.tokCh:
		return tok, nil
	case err := <-o.errCh:
		return nil, err
	case <-time.After(2 * time.Minute):
		return nil, errors.New("oauth command timed out, please try again")
	}
}

// DoManualAuthorization performs the log in into the identity provider
// allowing the user to open a browser on a different system and then entering
// the authorization code on the Step CLI.
func (o *oauth) DoManualAuthorization() (*token, error) {
	o.redirectURI = oobCallbackUrn
	authURL, err := o.Auth()
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(os.Stderr, "Open a local web browser and visit:")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, authURL)
	fmt.Fprintln(os.Stderr)

	// Read from the command line
	fmt.Fprint(os.Stderr, "Enter verification code: ")
	code, err := utils.ReadString(os.Stdin)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	tok, err := o.Exchange(o.tokenEndpoint, code)
	if err != nil {
		return nil, err
	}
	if tok.Err != "" || tok.ErrDesc != "" {
		return nil, errors.Errorf("Error exchanging authorization code: %s. %s", tok.Err, tok.ErrDesc)
	}
	return tok, nil
}

type identifyDeviceResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	// NOTE Google returns `verification_url` which is incorrect
	// according to the spec (https://datatracker.ietf.org/doc/html/rfc8628#section-3.2)
	// but we'll try to accommodate for that here.
	VerificationURL         string `json:"verification_url"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DoDeviceAuthorization gets a token from the IDP using the OAuth 2.0
// Device Authorization Grant. https://datatracker.ietf.org/doc/html/rfc8628
func (o *oauth) DoDeviceAuthorization() (*token, error) {
	// Identify the Device
	data := url.Values{}
	data.Set("client_id", o.clientID)
	data.Set("client_secret", o.clientSecret)
	data.Set("scope", o.scope)

	resp, err := postForm(o.deviceAuthzEndpoint, data)
	if err != nil {
		return nil, errors.Wrap(err, "http failure to identify device")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var e struct {
			Error string
		}
		if err := json.NewDecoder(bytes.NewReader(b)).Decode(&e); err != nil {
			return nil, errors.Wrapf(err, "could not parse http body: %s", string(b))
		}
	}

	var idr identifyDeviceResponse
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&idr); err != nil {
		return nil, errors.Wrap(err, "failure decoding device authz response to JSON")
	}

	switch {
	case idr.VerificationURI != "":
		// do nothing
	case idr.VerificationURL != "":
		// NOTE this is a hack for Google, because their API returns the attribute
		// 'verification_url` rather than `verification_uri`.
		idr.VerificationURI = idr.VerificationURL
	default:
		return nil, errors.Errorf("device code response from server missing 'verification_uri' parameter. http body response: %s", string(b))
	}

	if idr.Interval <= 0 {
		idr.Interval = defaultDeviceAuthzInterval
	}

	fmt.Fprintf(os.Stderr, "Visit %s and enter the code:\n", idr.VerificationURI)
	fmt.Fprintln(os.Stderr, idr.UserCode)

	// Poll the Token endpoint until the user completes the flow.
	data = url.Values{}
	data.Set("client_id", o.clientID)
	data.Set("client_secret", o.clientSecret)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", idr.DeviceCode)

	endPollIn := defaultDeviceAuthzExpiresIn
	if idr.ExpiresIn > 0 {
		expiresIn := time.Duration(idr.ExpiresIn) * time.Second
		if expiresIn < endPollIn {
			endPollIn = expiresIn
		}
	}

	t := time.NewTimer(endPollIn)
	defer t.Stop()
	for {
		select {
		case <-time.After(time.Duration(idr.Interval) * time.Second):
			tok, err := o.deviceAuthzTokenPoll(data)
			if errors.Is(err, errHTTPToken) {
				continue
			} else if err != nil {
				return nil, err
			}
			return tok, nil
		case <-t.C:
			return nil, errors.New("device authorization grant expired")
		}
	}
}

var errHTTPToken = errors.New("bad request; token not returned")

func (o *oauth) deviceAuthzTokenPoll(data url.Values) (*token, error) {
	resp, err := postForm(o.tokenEndpoint, data)
	if err != nil {
		return nil, errors.Wrap(err, "error doing POST to /token endpoint")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error reading HTTP response body from /token endpoint")
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		tok := token{}
		if err := json.NewDecoder(bytes.NewReader(b)).Decode(&tok); err != nil {
			return nil, errors.Wrap(err, "error parsing JSON /token response")
		}
		return &tok, nil
	case resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError:
		return nil, errHTTPToken
	default:
		return nil, errors.New(string(b))
	}
}

// DoTwoLeggedAuthorization performs two-legged OAuth using the jwt-bearer
// grant type.
func (o *oauth) DoTwoLeggedAuthorization(issuer string) (*token, error) {
	pemBytes := []byte(o.clientSecret)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to read private key pem block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing private key")
	}

	// Add claims
	now := int(time.Now().Unix())
	c := map[string]interface{}{
		"aud":   o.tokenEndpoint,
		"nbf":   now,
		"iat":   now,
		"exp":   now + 3600,
		"iss":   issuer,
		"scope": o.scope,
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", o.clientID)

	// Sign JWT
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: "RS256",
		Key:       priv,
	}, so)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating JWT signer")
	}

	raw, err := jose.Signed(signer).Claims(c).CompactSerialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing JWT")
	}

	// Construct the POST request to fetch the OAuth token.
	params := url.Values{
		"assertion":  []string{raw},
		"grant_type": []string{jwtBearerUrn},
	}

	// Send the POST request and return token.
	resp, err := postForm(o.tokenEndpoint, params)
	if err != nil {
		return nil, errors.Wrapf(err, "error from token endpoint")
	}
	defer resp.Body.Close()

	var tok token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, errors.WithStack(err)
	}

	return &tok, nil
}

// DoJWTAuthorization generates a JWT instead of an OAuth token. Only works for
// certain APIs. See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth.
func (o *oauth) DoJWTAuthorization(issuer, aud string) (*token, error) {
	pemBytes := []byte(o.clientSecret)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to read private key pem block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing private key")
	}

	// Add claims
	now := int(time.Now().Unix())
	c := map[string]interface{}{
		"aud": aud,
		"nbf": now,
		"iat": now,
		"exp": now + 3600,
		"iss": issuer,
		"sub": issuer,
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("kid", o.clientID)

	// Sign JWT
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: "RS256",
		Key:       priv,
	}, so)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating JWT signer")
	}

	raw, err := jose.Signed(signer).Claims(c).CompactSerialize()
	if err != nil {
		return nil, errors.Wrapf(err, "error serializing JWT")
	}

	tok := &token{raw, "", "", 3600, "Bearer", "", "", ""}
	return tok, nil
}

// ServeHTTP is the handler that performs the OAuth 2.0 dance and returns the
// tokens using channels.
func (o *oauth) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != o.CallbackPath {
		http.NotFound(w, req)
		return
	}

	if req.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		w.Write(nil)
		return
	}

	q := req.URL.Query()
	errStr := q.Get("error")
	if errStr != "" {
		o.badRequest(w, "Failed to authenticate: "+errStr)
		return
	}

	if o.implicit {
		o.implicitHandler(w, req)
		return
	}

	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		fmt.Fprintf(os.Stderr, "Invalid request received: http://%s%s\n", req.RemoteAddr, req.URL.String())
		fmt.Fprintf(os.Stderr, "You may have an app or browser plugin that needs to be turned off\n")
		http.Error(w, "400 bad request", http.StatusBadRequest)
		return
	}

	if code == "" {
		o.badRequest(w, "Failed to authenticate: missing or invalid code")
		return
	}

	if state == "" || state != o.state {
		o.badRequest(w, "Failed to authenticate: missing or invalid state")
		return
	}

	tok, err := o.Exchange(o.tokenEndpoint, code)
	if err != nil {
		o.badRequest(w, "Failed exchanging authorization code: "+err.Error())
		return
	}
	if tok.Err != "" || tok.ErrDesc != "" {
		o.badRequest(w, fmt.Sprintf("Failed exchanging authorization code: %s. %s", tok.Err, tok.ErrDesc))
		return
	}

	if o.terminalRedirect != "" {
		http.Redirect(w, req, o.terminalRedirect, http.StatusFound)
	} else {
		o.success(w)
	}
	o.tokCh <- tok
}

func (o *oauth) implicitHandler(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	if hash := q.Get("urlhash"); hash == "true" {
		state := q.Get("state")
		if state == "" || state != o.state {
			o.badRequest(w, "Failed to authenticate: missing or invalid state")
			return
		}
		accessToken := q.Get("access_token")
		if accessToken == "" {
			o.badRequest(w, "Failed to authenticate: missing access token")
			return
		}

		if o.terminalRedirect != "" {
			http.Redirect(w, req, o.terminalRedirect, http.StatusFound)
		} else {
			o.success(w)
		}

		expiresIn, _ := strconv.Atoi(q.Get("expires_in"))
		o.tokCh <- &token{
			AccessToken:  accessToken,
			IDToken:      q.Get("id_token"),
			RefreshToken: q.Get("refresh_token"),
			ExpiresIn:    expiresIn,
			TokenType:    q.Get("token_type"),
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<html><head><title>Processing OAuth Request</title>`))
	w.Write([]byte(`</head>`))
	w.Write([]byte(`<script type="text/javascript">`))
	fmt.Fprintf(w, `function redirect(){var hash = window.location.hash.substr(1); document.location.href = "%s?urlhash=true&"+hash;}`, o.redirectURI)
	w.Write([]byte(`if (window.addEventListener) window.addEventListener("load", redirect, false); else if (window.attachEvent) window.attachEvent("onload", redirect); else window.onload = redirect;`))
	w.Write([]byte("</script>"))
	w.Write([]byte(`<body><p style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
	w.Write([]byte(`<strong style='font-size: 28px; color: #000;'>Success</strong><br />`))
	w.Write([]byte(`Click <a href="javascript:redirect();">here</a> if your browser does not automatically redirect you`))
	w.Write([]byte(`</p></body></html>`))
}

// Auth returns the OAuth 2.0 authentication url.
func (o *oauth) Auth() (string, error) {
	u, err := url.Parse(o.authzEndpoint)
	if err != nil {
		return "", errors.WithStack(err)
	}

	q := u.Query()
	q.Add("client_id", o.clientID)
	q.Add("redirect_uri", o.redirectURI)
	if o.implicit {
		q.Add("response_type", "id_token token")
	} else {
		q.Add("response_type", "code")
		q.Add("code_challenge_method", "S256")
		s256 := sha256.Sum256([]byte(o.codeChallenge))
		q.Add("code_challenge", base64.RawURLEncoding.EncodeToString(s256[:]))
	}
	q.Add("scope", o.scope)
	if o.prompt != "" {
		q.Add("prompt", o.prompt)
	}
	q.Add("state", o.state)
	q.Add("nonce", o.nonce)
	if o.loginHint != "" {
		q.Add("login_hint", o.loginHint)
	}
	for k, vs := range o.authParams {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange exchanges the authorization code for refresh and access tokens.
func (o *oauth) Exchange(tokenEndpoint, code string) (*token, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", o.clientID)
	data.Set("client_secret", o.clientSecret)
	data.Set("redirect_uri", o.redirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", o.codeChallenge)

	resp, err := postForm(tokenEndpoint, data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer resp.Body.Close()

	var tok token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, errors.WithStack(err)
	}

	return &tok, nil
}

func (o *oauth) success(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")

	w.Write([]byte(`<html lang="en-US">`))
	w.Write([]byte(`<head><title>OAuth Request Successful</title>`))
	w.Write([]byte(`</head>`))
	w.Write([]byte(`<body style='background-color: rgb(238, 246, 252);text-align:center;font-family: open sans, sans-serif; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
	w.Write([]byte(`<div style="margin:auto;width:56px;">`))
	w.Write([]byte(`<svg width="56" height="61" viewBox="0 0 56 61" fill="none" xmlns="http://www.w3.org/2000/svg" style="alignment: center">`))
	w.Write([]byte(`<g filter="url(#filter0_d)">`))
	w.Write([]byte(`<path fill-rule="evenodd" clip-rule="evenodd" d="M50 38.0623L50 22.5532C50 20.0715 48.6641 17.77 46.4774 16.485L33.7817 9.02489C31.4569 7.65849 28.5431 7.65849 26.2183 9.02489L13.5226 16.485C11.3359 17.77 10 20.0715 10 22.5532L10 38.0623C10 40.544 11.3359 42.8455 13.5226 44.1305L26.2183 51.5909C28.5431 52.957 31.4569 52.957 33.7817 51.5909L46.4774 44.1305C48.6641 42.8455 50 40.544 50 38.0623Z" fill="white"/>`))
	w.Write([]byte(`</g>`))
	w.Write([]byte(`<path d="M26.1994 21.6989C26.5136 23.3294 28.3272 24.7249 28.9555 25.1068L35.8387 29.2344C36.5098 29.6164 40.3227 31.9813 41.7936 36.2852C41.8364 36.388 41.9364 36.4615 42.0363 36.4615C42.1791 36.4615 42.3077 36.344 42.3077 36.1824V24.5633C42.3077 23.917 41.9649 23.3147 41.408 23.0063L40.1085 22.2718C39.8372 22.1249 39.5087 22.2131 39.3516 22.4922L37.5523 25.7091C37.3952 25.9882 37.0525 26.0763 36.7812 25.9147L31.4689 22.7566C31.1976 22.595 31.1119 22.2424 31.269 21.9633L32.9969 18.8786C33.1682 18.5702 33.0397 18.1883 32.7256 18.056C32.1829 17.821 31.526 17.586 31.4689 17.5566C30.1123 17.1013 28.1987 16.9397 27.2848 18.3205C26.6421 19.2899 25.971 20.4651 26.1994 21.6989Z" fill="#DC4B40"/>`))
	w.Write([]byte(`<path d="M34.5697 38.9163C34.2555 37.2859 32.4419 35.8904 31.8136 35.5085L24.9304 31.3808C24.2593 30.9989 20.4464 28.634 18.9755 24.3301C18.9327 24.2273 18.8327 24.1538 18.7328 24.1538C18.5899 24.1538 18.4614 24.2713 18.4614 24.4329V36.0667C18.4614 36.713 18.8042 37.3152 19.3611 37.6237L20.6606 38.3582C20.9319 38.5051 21.2604 38.4169 21.4175 38.1378L23.2025 34.9209C23.3596 34.6418 23.7023 34.5537 23.9736 34.7153L29.2859 37.8734C29.5573 38.035 29.6429 38.3875 29.4859 38.6666L27.7722 41.7367C27.6009 42.0451 27.7294 42.427 28.0435 42.5592C28.5862 42.7943 29.2431 43.0293 29.3002 43.0587C30.6426 43.514 32.5561 43.6756 33.4701 42.2948C34.127 41.3254 34.7982 40.1502 34.5697 38.9163Z" fill="#DC4B40"/>`))
	w.Write([]byte(`<defs>`))
	w.Write([]byte(`<filter id="filter0_d" x="0" y="0" width="56" height="60.6154" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">`))
	w.Write([]byte(`<feFlood flood-opacity="0" result="BackgroundImageFix"/>`))
	w.Write([]byte(`<feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0"/>`))
	w.Write([]byte(`<feOffset dx="-2"/>`))
	w.Write([]byte(`<feGaussianBlur stdDeviation="4"/>`))
	w.Write([]byte(`<feColorMatrix type="matrix" values="0 0 0 0 0.13245 0 0 0 0 0.185971 0 0 0 0 0.444462 0 0 0 0.211532 0"/>`))
	w.Write([]byte(`<feBlend mode="normal" in2="BackgroundImageFix" result="effect1_dropShadow"/>`))
	w.Write([]byte(`<feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape"/>`))
	w.Write([]byte(`</filter>`))
	w.Write([]byte(`</defs>`))
	w.Write([]byte(`</svg>`))
	w.Write([]byte(`</div>`))
	w.Write([]byte(`<p style='font-size: 20px;'>`))
	w.Write([]byte(`<strong style='font-size: 28px; color: #000;'>Success</strong><br/>OAuth Request Successful.<br/>Look for the token on the command line.`))
	w.Write([]byte(`</p>`))
	w.Write([]byte(`</body>`))
	w.Write([]byte(`</html>`))
}

func (o *oauth) badRequest(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(`<html lang="en-US">`))
	w.Write([]byte(`<head><title>OAuth Request Unsuccessful</title>`))
	w.Write([]byte(`</head>`))
	w.Write([]byte(`<body style='background-color: rgb(238, 246, 252);text-align:center;font-family: open sans, sans-serif; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
	w.Write([]byte(`<div style="margin:auto;width:56px;">`))
	w.Write([]byte(`<svg width="56" height="61" viewBox="0 0 56 61" fill="none" xmlns="http://www.w3.org/2000/svg" style="alignment: center">`))
	w.Write([]byte(`<g filter="url(#filter0_d)">`))
	w.Write([]byte(`<path fill-rule="evenodd" clip-rule="evenodd" d="M50 38.0623L50 22.5532C50 20.0715 48.6641 17.77 46.4774 16.485L33.7817 9.02489C31.4569 7.65849 28.5431 7.65849 26.2183 9.02489L13.5226 16.485C11.3359 17.77 10 20.0715 10 22.5532L10 38.0623C10 40.544 11.3359 42.8455 13.5226 44.1305L26.2183 51.5909C28.5431 52.957 31.4569 52.957 33.7817 51.5909L46.4774 44.1305C48.6641 42.8455 50 40.544 50 38.0623Z" fill="white"/>`))
	w.Write([]byte(`</g>`))
	w.Write([]byte(`<path d="M26.1994 21.6989C26.5136 23.3294 28.3272 24.7249 28.9555 25.1068L35.8387 29.2344C36.5098 29.6164 40.3227 31.9813 41.7936 36.2852C41.8364 36.388 41.9364 36.4615 42.0363 36.4615C42.1791 36.4615 42.3077 36.344 42.3077 36.1824V24.5633C42.3077 23.917 41.9649 23.3147 41.408 23.0063L40.1085 22.2718C39.8372 22.1249 39.5087 22.2131 39.3516 22.4922L37.5523 25.7091C37.3952 25.9882 37.0525 26.0763 36.7812 25.9147L31.4689 22.7566C31.1976 22.595 31.1119 22.2424 31.269 21.9633L32.9969 18.8786C33.1682 18.5702 33.0397 18.1883 32.7256 18.056C32.1829 17.821 31.526 17.586 31.4689 17.5566C30.1123 17.1013 28.1987 16.9397 27.2848 18.3205C26.6421 19.2899 25.971 20.4651 26.1994 21.6989Z" fill="#DC4B40"/>`))
	w.Write([]byte(`<path d="M34.5697 38.9163C34.2555 37.2859 32.4419 35.8904 31.8136 35.5085L24.9304 31.3808C24.2593 30.9989 20.4464 28.634 18.9755 24.3301C18.9327 24.2273 18.8327 24.1538 18.7328 24.1538C18.5899 24.1538 18.4614 24.2713 18.4614 24.4329V36.0667C18.4614 36.713 18.8042 37.3152 19.3611 37.6237L20.6606 38.3582C20.9319 38.5051 21.2604 38.4169 21.4175 38.1378L23.2025 34.9209C23.3596 34.6418 23.7023 34.5537 23.9736 34.7153L29.2859 37.8734C29.5573 38.035 29.6429 38.3875 29.4859 38.6666L27.7722 41.7367C27.6009 42.0451 27.7294 42.427 28.0435 42.5592C28.5862 42.7943 29.2431 43.0293 29.3002 43.0587C30.6426 43.514 32.5561 43.6756 33.4701 42.2948C34.127 41.3254 34.7982 40.1502 34.5697 38.9163Z" fill="#DC4B40"/>`))
	w.Write([]byte(`<defs>`))
	w.Write([]byte(`<filter id="filter0_d" x="0" y="0" width="56" height="60.6154" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">`))
	w.Write([]byte(`<feFlood flood-opacity="0" result="BackgroundImageFix"/>`))
	w.Write([]byte(`<feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0"/>`))
	w.Write([]byte(`<feOffset dx="-2"/>`))
	w.Write([]byte(`<feGaussianBlur stdDeviation="4"/>`))
	w.Write([]byte(`<feColorMatrix type="matrix" values="0 0 0 0 0.13245 0 0 0 0 0.185971 0 0 0 0 0.444462 0 0 0 0.211532 0"/>`))
	w.Write([]byte(`<feBlend mode="normal" in2="BackgroundImageFix" result="effect1_dropShadow"/>`))
	w.Write([]byte(`<feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape"/>`))
	w.Write([]byte(`</filter>`))
	w.Write([]byte(`</defs>`))
	w.Write([]byte(`</svg>`))
	w.Write([]byte(`</div>`))
	w.Write([]byte(`<p style='font-size: 20px;'>`))
	w.Write([]byte(`<strong style='font-size: 28px; color: red;'>Failure</strong><br />`))
	w.Write([]byte(msg))
	w.Write([]byte(`</p></body></html>`))
	o.errCh <- errors.New(msg)
}
