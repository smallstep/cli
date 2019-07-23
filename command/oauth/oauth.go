package oauth

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/exec"
	"github.com/smallstep/cli/jose"
)

type oauth struct {
	provider           string
	clientID           string
	clientSecret       string
	scope              string
	audience           string
	loginHint          string
	redirectURI        string
	tokenEndpoint      string
	authzEndpoint      string
	revocationEndpoint string
	userInfoEndpoint   string // For testing
	state              string
	codeChallenge      string
	nonce              string
	implicit           bool
	errCh              chan error
	tokCh              chan *token
}

func newOauth(provider, clientID, clientSecret string, opts *options) (*oauth, error) {
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

	switch provider {
	case "google":
		return &oauth{
			provider:           provider,
			clientID:           clientID,
			clientSecret:       clientSecret,
			scope:              opts.Scope,
			audience:           opts.Audience,
			authzEndpoint:      "https://accounts.google.com/o/oauth2/v2/auth",
			tokenEndpoint:      "https://www.googleapis.com/oauth2/v4/token",
			revocationEndpoint: "https://oauth2.googleapis.com/revoke",
			userInfoEndpoint:   "https://www.googleapis.com/oauth2/v3/userinfo",
			loginHint:          opts.Email,
			state:              state,
			codeChallenge:      challenge,
			nonce:              nonce,
			implicit:           opts.Implicit,
			errCh:              make(chan error),
			tokCh:              make(chan *token),
		}, nil
	default:
		var userinfoEp string
		if provider != "" {
			d, err := disco(provider)
			if err != nil {
				return nil, err
			}

			if v, ok := d["authorization_endpoint"].(string); ok && opts.AuthzEndpoint == "" {
				opts.AuthzEndpoint = v
			}
			if v, ok := d["token_endpoint"].(string); ok && opts.TokenEndpoint == "" {
				opts.TokenEndpoint = v
			}
			if v, ok := d["revocation_endpoint"].(string); ok && opts.RevokeEndpoint == "" {
				opts.RevokeEndpoint = v
			}
			if v, ok := d["userinfo_endpoint"].(string); ok {
				userinfoEp = v
			}
			switch {
			case opts.AuthzEndpoint == "":
				return nil, errors.New("missing 'authorization_endpoint' in provider metadata")
			case opts.TokenEndpoint == "":
				return nil, errors.New("missing 'token_endpoint' in provider metadata")
			}
		}
		return &oauth{
			provider:           provider,
			clientID:           clientID,
			clientSecret:       clientSecret,
			scope:              opts.Scope,
			audience:           opts.Audience,
			authzEndpoint:      opts.AuthzEndpoint,
			tokenEndpoint:      opts.TokenEndpoint,
			revocationEndpoint: opts.RevokeEndpoint,
			userInfoEndpoint:   userinfoEp,
			loginHint:          opts.Email,
			state:              state,
			codeChallenge:      challenge,
			nonce:              nonce,
			implicit:           opts.Implicit,
			errCh:              make(chan error),
			tokCh:              make(chan *token),
		}, nil
	}
}

func disco(provider string) (map[string]interface{}, error) {
	url, err := url.Parse(provider)
	if err != nil {
		return nil, err
	}
	// TODO: OIDC and OAuth specify two different ways of constructing this
	// URL. This is the OIDC way. Probably want to try both. See
	// https://tools.ietf.org/html/rfc8414#section-5
	if strings.Index(url.Path, "/.well-known/openid-configuration") == -1 {
		url.Path = path.Join(url.Path, "/.well-known/openid-configuration")
	}
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving %s", url.String())
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving %s", url.String())
	}
	details := make(map[string]interface{})
	if err := json.Unmarshal(b, &details); err != nil {
		return nil, errors.Wrapf(err, "error reading %s: unsupported format", url.String())
	}
	return details, err
}

// DoLoopbackAuthorization performs the log in into the identity provider
// opening a browser and using a redirect_uri in a loopback IP address
// (http://127.0.0.1:port or http://[::1]:port).
func (o *oauth) DoLoopbackAuthorization() (*token, error) {
	srv := httptest.NewServer(o)
	o.redirectURI = srv.URL
	defer srv.Close()

	// Get auth url and open it in a browser
	authURL, err := o.Auth()
	if err != nil {
		return nil, err
	}

	if err := exec.OpenInBrowser(authURL); err != nil {
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
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
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

// DoRefreshToken performs a the non-interactive refresh_token grant type.
func (o *oauth) DoRefreshToken(refreshToken string) (*token, error) {
	data := url.Values{}
	data.Set("scope", o.scope)
	data.Set("client_id", o.clientID)
	data.Set("client_secret", o.clientSecret)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	if o.audience != "" {
		data.Set("audience", o.audience)
	}

	// Send the POST request to obtain the token(s).
	resp, err := http.PostForm(o.tokenEndpoint, data)
	if err != nil {
		return nil, errors.Wrap(err, "error from token endpoint")
	}
	defer resp.Body.Close()

	var tok token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, errors.WithStack(err)
	}

	return &tok, nil
}

// DoRevoke revokes an access or refresh token using the OAuth 2.0 Token
// Revocation protocol defined in RFC7009.
func (o *oauth) DoRevoke(token string) error {
	params := url.Values{
		"token": []string{token},
	}

	// Send the POST request to revoke the token
	resp, err := http.PostForm(o.revocationEndpoint, params)
	if err != nil {
		return errors.Wrap(err, "error from revocation endpoint")
	}
	defer resp.Body.Close()

	var tok map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// DoTwoLeggedAuthorization performs two-legged OAuth using the jwt-bearer
// grant type.
func (o *oauth) DoTwoLeggedAuthorization(issuer, audience string) (*token, error) {
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
		"aud": o.tokenEndpoint,
		"nbf": now,
		"iat": now,
		"exp": now + 3600,
		"iss": issuer,
	}
	if audience != "" {
		c["target_audience"] = audience
	} else {
		c["scope"] = o.scope
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
		"assertion":  []string{string(raw)},
		"grant_type": []string{jwtBearerUrn},
	}

	// Send the POST request and return token.
	resp, err := http.PostForm(o.tokenEndpoint, params)
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

	tok := &token{string(raw), "", "", 3600, "Bearer", "", ""}
	return tok, nil
}

// ServeHTTP is the handler that performs the OAuth 2.0 dance and returns the
// tokens using channels.
func (o *oauth) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
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

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(`<html><head><title>OAuth Request Successful</title>`))
	w.Write([]byte(`</head><body><p style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
	w.Write([]byte(`<strong style='font-size: 28px; color: #000;'>Success</strong><br />Look for the token on the command line`))
	w.Write([]byte(`</p></body></html>`))
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

		w.WriteHeader(http.StatusOK)
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(`<html><head><title>OAuth Request Successful</title>`))
		w.Write([]byte(`</head><body><p style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
		w.Write([]byte(`<strong style='font-size: 28px; color: #000;'>Success</strong><br />Look for the token on the command line`))
		w.Write([]byte(`</p></body></html>`))

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
	w.Write([]byte(fmt.Sprintf(`function redirect(){var hash = window.location.hash.substr(1); document.location.href = "%s?urlhash=true&"+hash;}`, o.redirectURI)))
	w.Write([]byte(`if (window.addEventListener) window.addEventListener("load", redirect, false); else if (window.attachEvent) window.attachEvent("onload", redirect); else window.onload = redirect;`))
	w.Write([]byte("</script>"))
	w.Write([]byte(`<body><p style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
	w.Write([]byte(`<strong style='font-size: 28px; color: #000;'>Success</strong><br />`))
	w.Write([]byte(`Click <a href="javascript:redirect();">here</a> if your browser does not automatically redirect you`))
	w.Write([]byte(`</p></body></html>`))
	return
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
	q.Add("state", o.state)
	q.Add("nonce", o.nonce)
	if o.loginHint != "" {
		q.Add("login_hint", o.loginHint)
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
	if o.audience != "" {
		data.Set("audience", o.audience)
	}

	resp, err := http.PostForm(tokenEndpoint, data)
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

func (o *oauth) badRequest(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(`<html><head><title>OAuth Request Unsuccessful</title>`))
	w.Write([]byte(`</head><body><p style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>`))
	w.Write([]byte(`<strong style='font-size: 28px; color: red;'>Failure</strong><br />`))
	w.Write([]byte(msg))
	w.Write([]byte(`</p></body></html>`))
	o.errCh <- errors.New(msg)
}
