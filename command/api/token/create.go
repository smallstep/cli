package token

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/google/uuid"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"

	"github.com/smallstep/cli/internal/cryptoutil"
	"github.com/smallstep/cli/internal/httptransport"
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

	var (
		args       = ctx.Args()
		teamID     = args.Get(0)
		crtFile    = args.Get(1)
		keyFile    = args.Get(2)
		apiURLFlag = ctx.String("api-url")
		audience   = ctx.String("audience")
	)

	parsedURL, err := url.Parse(apiURLFlag)
	if err != nil {
		return err
	}
	parsedURL.Path = path.Join(parsedURL.Path, "api/auth")
	apiURL := parsedURL.String()

	clientCert, err := createClientCertificate(crtFile, keyFile)
	if err != nil {
		return err
	}

	b := new(bytes.Buffer)
	r := createTokenReq{
		Bundle:   clientCert.Certificate,
		Audience: audience,
	}

	if err := uuid.Validate(teamID); err != nil {
		r.TeamSlug = teamID
	} else {
		r.TeamID = teamID
	}

	if err := json.NewEncoder(b).Encode(r); err != nil {
		return err
	}

	transport := httptransport.New()
	transport.TLSClientConfig = &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
		MinVersion: tls.VersionTLS12,
	}
	client := http.Client{
		Transport: transport,
	}

	req, err := http.NewRequest("POST", apiURL, b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ca.UserAgent) // this is set to step.Version() during init; i.e. "Smallstep CLI/vX.X.X (os/arch)"
	req.Header.Set(requestIDHeader, newRequestID())

	resp, err := client.Do(req)
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

// requestIDHeader is the header name used for propagating request IDs from
// the client to the server and back again.
const requestIDHeader = "X-Request-Id"

// newRequestID generates a new random UUIDv4 request ID. If it fails,
// the request ID will be the empty string.
func newRequestID() string {
	requestID, err := randutil.UUIDv4()
	if err != nil {
		return ""
	}

	return requestID
}

func createClientCertificate(crtFile, keyFile string) (*tls.Certificate, error) {
	certs, err := pemutil.ReadCertificateBundle(crtFile)
	if err != nil {
		return nil, fmt.Errorf("failed reading %q: %w", crtFile, err)
	}

	var certificates = make([][]byte, len(certs))
	for i, c := range certs {
		certificates[i] = c.Raw
	}

	var (
		v      any
		signer crypto.Signer
	)
	if cryptoutil.IsKMS(keyFile) {
		signer, err = cryptoutil.CreateSigner(keyFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed creating signer: %w", err)
		}
		v = signer
	} else {
		v, err = pemutil.Read(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed reading %q: %w", keyFile, err)
		}
	}

	return &tls.Certificate{
		Certificate: certificates,
		Leaf:        certs[0],
		PrivateKey:  v,
	}, nil
}
