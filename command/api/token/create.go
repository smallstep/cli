package token

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/google/uuid"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
)

func createCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Action: cli.ActionFunc(createAction),
		Usage:  "create a new token",
		UsageText: `**step api token create** <team> <crt-file> <key-file>
[**--api-url**=<url>] [**--audience**=<name>]
`,
		Flags: []cli.Flag{
			apiURLFlag,
			audienceFlag,
		},
		Description: `**step ca api token create** creates a new token for connecting to the Smallstep API.

## POSITIONAL ARGUMENTS

<team>
:  UUID or slug of the team the API token will be issued for. This is available in the Smallstep dashboard.

<crt-file>
:  File to read the certificate (PEM format). This certificate must be signed by a trusted root configured in the Smallstep dashboard.

<key-file>
:  File to read the private key (PEM format).

## EXAMPLES
Use a certificate to get a new API token:
'''
$ step api token create ff98be70-7cc3-4df5-a5db-37f5d3c96e23 internal.crt internal.key
'''

Get a token using the team slug:
'''
$ step api token create teamfoo internal.crt internal.key
'''
`,
	}
}

type createTokenReq struct {
	TeamID   string   `json:"teamID"`
	TeamSlug string   `json:"teamSlug"`
	Bundle   [][]byte `json:"bundle"`
	Audience string   `json:"audience,omitempty"`
}

type createTokenResp struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

func createAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	args := ctx.Args()

	teamID := args.Get(0)
	crtFile := args.Get(1)
	keyFile := args.Get(2)

	parsedURL, err := url.Parse(ctx.String("api-url"))
	if err != nil {
		return err
	}
	parsedURL.Path = path.Join(parsedURL.Path, "api/auth")
	apiURL := parsedURL.String()

	clientCert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return err
	}
	b := &bytes.Buffer{}
	r := &createTokenReq{
		Bundle:   clientCert.Certificate,
		Audience: ctx.String("audience"),
	}
	if err := uuid.Validate(teamID); err != nil {
		r.TeamSlug = teamID
	} else {
		r.TeamID = teamID
	}
	err = json.NewEncoder(b).Encode(r)
	if err != nil {
		return err
	}

	post, err := http.NewRequest("POST", apiURL, b)
	if err != nil {
		return err
	}
	post.Header.Set("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		},
		MinVersion: tls.VersionTLS12,
	}
	client := http.Client{
		Transport: transport,
	}
	resp, err := client.Do(post)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody := &createTokenResp{}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		if respBody.Message != "" {
			return errors.New(respBody.Message)
		}
		return fmt.Errorf("failed to create token: %d", resp.StatusCode)
	}

	// Print message to stderr for humans and token to stdout for scripts
	ui.PrintSelected("Token successfully created", "")
	fmt.Println(respBody.Token)

	return nil
}
