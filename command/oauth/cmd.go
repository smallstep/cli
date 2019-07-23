package oauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
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
	defaultClientID          = "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com"
	defaultClientNotSoSecret = "udTrOT3gzrO7W9fDPgZQLfYJ"

	// The URN for getting verification token offline
	oobCallbackUrn = "urn:ietf:wg:oauth:2.0:oob"
	// The URN for token request grant type jwt-bearer
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
}

func init() {
	cmd := cli.Command{
		Name:  "oauth",
		Usage: "authorization and single sign-on using OAuth & OIDC",
		UsageText: `
**step oauth** [**--provider**=<provider>] [**--client-id**=<client-id> **--client-secret**=<client-secret>]
  [**--scope**=<scope> ...] [**--bare** [**--oidc**]] [**--header** [**--oidc**]]

**step oauth** **--authorization-endpoint**=<authorization-endpoint> **--token-endpoint**=<token-endpoint>
  **--client-id**=<client-id> **--client-secret**=<client-secret> [**--scope**=<scope> ...] [**--bare** [**--oidc**]] [**--header** [**--oidc**]]

**step oauth** [**--account**=<account>] [**--authorization-endpoint**=<authorization-endpoint> **--token-endpoint**=<token-endpoint>]
  [**--scope**=<scope> ...] [**--bare** [**--oidc**]] [**--header** [**--oidc**]]

**step oauth** **--account**=<account> **--jwt** [**--scope**=<scope> ...] [**--header**] [**-bare**]
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "provider, idp",
				Usage: "OAuth provider for authentication",
				Value: "google",
			},
			cli.StringFlag{
				Name:  "refresh",
				Usage: "Refresh existing OAuth/OIDC token(s) using a refresh <token> with the refresh grant type",
			},
			cli.StringFlag{
				Name:  "revoke",
				Usage: "Revoke an OAuth access or refresh <token>",
			},
			cli.StringFlag{
				Name:  "email, e",
				Usage: "Email to authenticate",
			},
			cli.BoolFlag{
				Name:  "console, c",
				Usage: "Complete the flow while remaining only inside the terminal",
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
				Name:  "token-endpoint",
				Usage: "OAuth Token Endpoint",
			},
			cli.StringFlag{
				Name:  "revocation-endpoint",
				Usage: "OAuth Token Revocation Endpoint",
			},
			cli.BoolFlag{
				Name:  "header",
				Usage: "Output HTTP Authorization Header (suitable for use with curl)",
			},
			cli.BoolFlag{
				Name:  "oidc",
				Usage: "Output OIDC Token instead of OAuth Access Token",
			},
			cli.StringFlag{
				Name:  "audience, aud",
				Usage: "Audience of OAuth OIDC Token",
			},
			cli.BoolFlag{
				Name:  "bare",
				Usage: "Only output the token",
			},
			cli.StringSliceFlag{
				Name:  "scope",
				Usage: "OAuth scopes",
			},
			cli.BoolFlag{
				Name:  "jwt",
				Usage: "Generate a JWT Auth token instead of an OAuth Token (only works with service accounts)",
			},
			cli.BoolFlag{
				Name:   "implicit",
				Usage:  "Uses the implicit flow to authenticate the user. Requires **--insecure** and **--client-id** flags.",
				Hidden: true,
			},
			cli.BoolFlag{
				Name:   "insecure",
				Usage:  "Allows the use of insecure flows.",
				Hidden: true,
			},
		},
		Action: oauthCmd,
	}

	command.Register(cmd)
}

func oauthCmd(ctx *cli.Context) error {
	opts := newOptions(ctx)

	provider := ctx.String("provider")
	if provider != "google" && !strings.HasPrefix(provider, "https://") {
		return errs.InvalidFlagValue(ctx, "provider", ctx.String("provider"), "")
	}

	if provider != "google" && !(ctx.IsSet("client-id") || ctx.IsSet("revoke")) {
		return errs.RequiredWithFlag(ctx, "provider", "client-id")
	}

	var clientID, clientSecret string
	if opts.Implicit {
		if !ctx.Bool("insecure") {
			return errs.RequiredInsecureFlag(ctx, "implicit")
		}
		if !ctx.IsSet("client-id") {
			return errs.RequiredWithFlag(ctx, "implicit", "client-id")
		}
	} else {
		clientID = defaultClientID
		clientSecret = defaultClientNotSoSecret
	}
	if ctx.IsSet("client-id") {
		clientID = ctx.String("client-id")
		clientSecret = ctx.String("client-secret")
	}

	// Validate custom endpoints with client-id
	switch {
	case ctx.IsSet("authorization-endpoint") && !ctx.IsSet("client-id"):
		return errs.RequiredWithFlag(ctx, "authorization-endpoint", "client-id")
	case ctx.IsSet("authorization-endpoint") && !ctx.IsSet("token-endpoint"):
		return errs.RequiredWithFlag(ctx, "authorization-endpoint", "token-endpoint")
	case ctx.IsSet("token-endpoint") && !ctx.IsSet("client-id"):
		return errs.RequiredWithFlag(ctx, "token-endpoint", "client-id")
	}

	// Always set an empty provider if not set and custom endpoints are set
	if !ctx.IsSet("provider") {
		if ctx.IsSet("authorization-endpoint") || ctx.IsSet("token-endpoint") || ctx.IsSet("revocation-endpoint") {
			provider = ""
		}
	}

	var do2lo bool
	var issuer string

	// This code supports Google service accounts. Probably maybe also support JWKs?
	if ctx.IsSet("account") {
		provider = ""
		filename := ctx.String("account")
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading account from %s", filename)
		}
		account := make(map[string]interface{})
		if err := json.Unmarshal(b, &account); err != nil {
			return errors.Wrapf(err, "error reading %s: unsupported format", filename)
		}

		// TODO: Other client types are different
		if _, ok := account["installed"]; ok {
			details := account["installed"].(map[string]interface{})
			opts.AuthzEndpoint = details["auth_uri"].(string)
			opts.TokenEndpoint = details["token_uri"].(string)
			clientID = details["client_id"].(string)
			clientSecret = details["client_secret"].(string)
		} else if accountType, ok := account["type"].(string); ok && "service_account" == accountType {
			opts.AuthzEndpoint = account["auth_uri"].(string)
			opts.TokenEndpoint = account["token_uri"].(string)
			clientID = account["private_key_id"].(string)
			clientSecret = account["private_key"].(string)
			issuer = account["client_email"].(string)
			do2lo = true
		} else {
			return errors.Wrapf(err, "error reading %s: unsupported account type", filename)
		}
	}

	o, err := newOauth(provider, clientID, clientSecret, opts)
	if err != nil {
		return err
	}

	if ctx.IsSet("revoke") {
		if o.revocationEndpoint == "" {
			return errors.New("missing 'revocation_endpoint' in provider metadata")
		}
		return o.DoRevoke(ctx.String("revoke"))
	}

	var tok *token
	if do2lo {
		if ctx.Bool("jwt") {
			if ctx.IsSet("aud") {
				// TODO: This should be something like DoJWTClientCredentials or
				// DoJWTbAT or something? Might want to distinguish between those two:
				// - JWT client credentials (standardized)
				// - JWT-bAT (non-standardized? Google-only?)
				tok, err = o.DoJWTAuthorization(issuer, opts.Audience)
			} else {
				tok, err = o.DoJWTAuthorization(issuer, opts.Scope)
			}
		} else {
			tok, err = o.DoTwoLeggedAuthorization(issuer, opts.Audience)
		}
	} else if ctx.IsSet("refresh") {
		tok, err = o.DoRefreshToken(ctx.String("refresh"))
	} else if ctx.Bool("console") {
		tok, err = o.DoManualAuthorization()
	} else {
		tok, err = o.DoLoopbackAuthorization()
	}

	if err != nil {
		return err
	}

	if ctx.Bool("header") {
		if ctx.Bool("oidc") {
			fmt.Println("Authorization: Bearer", tok.IDToken)
		} else {
			fmt.Println("Authorization: Bearer", tok.AccessToken)
		}
	} else {
		if ctx.Bool("bare") {
			if ctx.Bool("oidc") {
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

type options struct {
	Audience       string
	Scope          string
	Email          string
	Implicit       bool
	AuthzEndpoint  string
	TokenEndpoint  string
	RevokeEndpoint string
}

func newOptions(ctx *cli.Context) *options {
	scope := "openid email"
	if ctx.IsSet("scope") {
		scope = strings.Join(ctx.StringSlice("scope"), " ")
	}
	return &options{
		Audience:       ctx.String("audience"),
		Scope:          scope,
		Email:          ctx.String("email"),
		Implicit:       ctx.Bool("implicit"),
		AuthzEndpoint:  ctx.String("authorization-endpoint"),
		TokenEndpoint:  ctx.String("token-endpoint"),
		RevokeEndpoint: ctx.String("revocation-endpoint"),
	}
}
