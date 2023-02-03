package token

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/ui"
)

func createCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Action: cli.ActionFunc(createAction),
		Usage:  "create a new token",
		UsageText: `**step api token create** <team-id> <crt-file> <key-file>
[**--api-url**=<url>]
`,
		Flags: []cli.Flag{
			apiURLFlag,
		},
		Description: `**step ca api token create** creates a new token for connecting to the Smallstep API.

## POSITIONAL ARGUMENTS

<team-id>
:  UUID of the team the API token will be issued for

<crt-file>
:  File to read the certificate (PEM format)

<key-file>
:  File to read the private key (PEM format)

## Examples

$ step api token create me.crt me.key
`,
	}
}

type createTokenReq struct {
	TeamID string   `json:"teamID"`
	Bundle [][]byte `json:"bundle"`
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

	apiURL := ctx.String("api-url")
	if apiURL == "" {
		apiURL = "https://gateway.smallstep.com"
	}
	apiURL, err = url.JoinPath(apiURL, "api/auth")
	if err != nil {
		return err
	}

	if _, err := uuid.Parse(teamID); err != nil {
		// TODO improve message
		return err
	}

	clientCert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return err
	}
	b := &bytes.Buffer{}
	r := &createTokenReq{
		TeamID: teamID,
		Bundle: clientCert.Certificate,
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
		return fmt.Errorf("Failed to create token: %d", resp.StatusCode)
	}

	// Print message to stderr for humans and token to stdout for scripts
	ui.PrintSelected("Token successfully created", "")
	fmt.Println(respBody.Token)

	return nil
}
