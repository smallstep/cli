package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/google/uuid"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/tss2"

	"github.com/smallstep/cli/flags"
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
			flags.PasswordFile,
			tpmDeviceFlag,
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
Use a certificate and team ID to get a new API token:
'''
$ step api token create ff98be70-7cc3-4df5-a5db-37f5d3c96e23 internal.crt internal.key
'''

Get a token using the team slug:
'''
$ step api token create team-foo internal.crt internal.key
'''

Use a certificate with a private key backed by a TPM to get a new API token:
'''
$ step api token create team-tpm ecdsa-chain.crt 'tpmkms:name=test-ecdsa'
'''

Use a certificate with a private key backed by a TPM simulator to get a new API token:
'''
$ step api token create team-tpm-simulator ecdsa-chain.crt 'tpmkms:name=test-ecdsa;device=/path/to/tpmsimulator.sock'
'''

Use a certificate and a TSS2 PEM encoded private key to get a new API token:
'''
$ step api token create team-tss2 ecdsa-chain.crt ecdsa.tss2.pem --tpm-device /dev/tpmrm0
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
		args         = ctx.Args()
		teamID       = args.Get(0)
		crtFile      = args.Get(1)
		keyFile      = args.Get(2)
		passwordFile = ctx.String("password-file")
		apiURLFlag   = ctx.String("api-url")
		audience     = ctx.String("audience")
		tpmDevice    = ctx.String("tpm-device")
	)

	parsedURL, err := url.Parse(apiURLFlag)
	if err != nil {
		return err
	}
	parsedURL.Path = path.Join(parsedURL.Path, "api/auth")
	apiURL := parsedURL.String()

	clientCert, err := createClientCertificate(crtFile, keyFile, passwordFile, tpmDevice)
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

func createClientCertificate(crtFile, keyFile, passwordFile, tpmDevice string) (*tls.Certificate, error) {
	certs, err := pemutil.ReadCertificateBundle(crtFile)
	if err != nil {
		return nil, fmt.Errorf("failed reading %q: %w", crtFile, err)
	}

	var certificates = make([][]byte, len(certs))
	for i, c := range certs {
		certificates[i] = c.Raw
	}

	pk, err := getPrivateKey(keyFile, passwordFile, tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("failed reading key from %q: %w", keyFile, err)
	}

	if _, ok := pk.(crypto.Signer); !ok {
		return nil, fmt.Errorf("private key type %T read from %q cannot be used as a signer", pk, keyFile)
	}

	return &tls.Certificate{
		Certificate: certificates,
		Leaf:        certs[0],
		PrivateKey:  pk,
	}, nil
}

func getPrivateKey(keyFile, passwordFile, tpmDevice string) (crypto.PrivateKey, error) {
	if cryptoutil.IsKMS(keyFile) {
		signer, err := cryptoutil.CreateSigner(keyFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed creating signer: %w", err)
		}

		return signer, nil
	}

	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	// detect the type of the PEM file. if it's a TSS2 PEM file, pemutil
	// can't be used to create a private key, as it does not support this
	// type. Support could be added, but it could require some additional
	// options, such as specifying the TPM device that backs the TSS2
	// signer.
	p, _ := pem.Decode(b)
	if p.Type != "TSS2 PRIVATE KEY" {
		var opts []pemutil.Options
		if passwordFile != "" {
			opts = append(opts, pemutil.WithPasswordFile(passwordFile))
		}

		pk, err := pemutil.Parse(b, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed parsing PEM: %w", err)
		}

		return pk, nil
	}

	key, err := tss2.ParsePrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed creating TSS2 private key: %w", err)
	}

	var tpmOpts = []tpm.NewTPMOption{}
	if tpmDevice != "" {
		tpmOpts = append(tpmOpts, tpm.WithDeviceName(tpmDevice))
	}

	t, err := tpm.New(tpmOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed initializing TPM: %w", err)
	}

	signer, err := tpm.CreateTSS2Signer(context.Background(), t, key)
	if err != nil {
		return nil, fmt.Errorf("failed creating TSS2 signer: %w", err)
	}

	return signer, nil
}
