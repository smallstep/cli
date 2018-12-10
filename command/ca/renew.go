package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

func renewCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "renew",
		Action: command.ActionFunc(renewCertificateAction),
		Usage:  "renew a valid certificate",
		UsageText: `**step ca renew** <crt-file> <key-file>
		[**--ca-url**=<uri>] [**--root**=<file>]
		[**--out**=<file>] [**--expires-in**=<duration>] [**--force**]`,
		Description: `
**step ca renew** command renews the given certificates on the certificate
authority and writes the new certificate to disk either overwriting <crt-file>
or using a new file if the **--out**=<file> flag is used.

## POSITIONAL ARGUMENTS

<crt-file>
:  The certificate in PEM format that we want to renew.

<key-file>
:  They key file of the certificate.

## EXAMPLES

Renew a certificate with the configured CA:
'''
$ step ca renew internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''

Renew a certificate without overwriting the previous certificate:
'''
$ step ca renew --out renewed.crt internal.crt internal.key
'''

Renew a certificate forcing the overwrite of the previous certificate:
'''
$ step ca renew --force internal.crt internal.key
'''

Renew a certificate providing the <--ca-url> and <--root> flags:
'''
$ step ca renew --ca-url https://ca.smallstep.com:9000 \
  --root /path/to/root_ca.crt internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''

Renew skipped because it was too early:
'''
$ step ca renew --expires-in 8h internal.crt internal.key
certificate not renewed: expires in 10h52m5s
'''`,
		Flags: []cli.Flag{
			caURLFlag,
			rootFlag,
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <crt-file> positional argument",
			},
			cli.StringFlag{
				Name: "expires-in",
				Usage: `The <duration> check that will be performed before renewing the certificate. The
certificate renew will be skipped if the time to expiration is greater than the
passed one. A random jitter (duration/20) will be added to avoid multiple
services hitting the renew endpoint at the same time. The <duration> is a
sequence of decimal numbers, each with optional fraction and a unit suffix, such
as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms",
"s", "m", "h".`,
			},
			flags.Force,
		},
	}
}

func renewCertificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()
	crtFile := args.Get(0)
	keyFile := args.Get(1)

	outFile := ctx.String("out")
	if len(outFile) == 0 {
		outFile = crtFile
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return errors.Wrap(err, "error loading certificates")
	}
	if len(cert.Certificate) == 0 {
		return errors.New("error loading certificate: certificate chain is empty")
	}

	// Do not renew if (now - cert.notBefore) > (expiresIn + jitter)
	if s := ctx.String("expires-in"); len(s) > 0 {
		duration, err := time.ParseDuration(s)
		if err != nil {
			return errs.InvalidFlagValue(ctx, "expires-in", s, "")
		}

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return errors.Wrap(err, "error parsing certificate")
		}

		now := time.Now()
		jitter := rand.Int63n(int64(duration / 20))
		if d := leaf.NotAfter.Sub(now); d > duration+time.Duration(jitter) {
			fmt.Printf("certificate not renewed: expires in %s\n", d.Round(time.Second))
			return nil
		}
	}

	rootInt, err := pemutil.Read(root)
	if err != nil {
		return err
	}

	rootCert, ok := rootInt.(*x509.Certificate)
	if !ok {
		return errors.Errorf("error parsing %s: file is not a root certificate", root)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			RootCAs:                  pool,
			PreferServerCipherSuites: true,
		},
	}

	client, err := ca.NewClient(caURL, ca.WithTransport(tr))
	if err != nil {
		return err
	}

	resp, err := client.Renew(tr)
	if err != nil {
		return errors.Wrap(err, "error renewing certificate")
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)

	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return errs.FileError(err, outFile)
	}

	ui.Printf("Your certificate has been saved in %s.\n", outFile)
	return nil
}
