package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
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
			cli.BoolFlag{
				Name: "daemon",
				Usage: `Run the renew command as a daemon, renewing the certificate when required, and
overwriting it if it's necessary. By default it will automatically renew the
certificate after 2/3 of the time to expire has passed. This behavior can be
changed using the flag **--expires-in**, in this case, it will only renew the
certificate if the time to expiration is greater than the passed one.`,
			},
			cli.IntFlag{
				Name: "pid",
				Usage: `The process id to signal after the certificate has been renewed. By default it
will use the SIGHUP (1) signal, but it can be configured with the **--signal**
flag.`,
			},
			cli.IntFlag{
				Name: "signal",
				Usage: `The signal <number> to send to the selected PID, so it can reload the
configuration and load the new certificate.`,
				Value: int(syscall.SIGHUP),
			},
		},
	}
}

func renewCertificateAction(ctx *cli.Context) error {
	err := errs.NumberOfArguments(ctx, 2)
	if err != nil {
		return err
	}

	args := ctx.Args()
	crtFile := args.Get(0)
	keyFile := args.Get(1)

	outFile := ctx.String("out")
	if len(outFile) == 0 {
		outFile = crtFile
	}

	rootFile := ctx.String("root")
	if len(rootFile) == 0 {
		rootFile = pki.GetRootCAPath()
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}

	var expiresIn time.Duration
	if s := ctx.String("expires-in"); len(s) > 0 {
		if expiresIn, err = time.ParseDuration(s); err != nil {
			return errs.InvalidFlagValue(ctx, "expires-in", s, "")
		}
	}

	pid := ctx.Int("pid")
	if ctx.IsSet("pid") && pid <= 0 {
		return errs.InvalidFlagValue(ctx, "pid", strconv.Itoa(pid), "")
	}

	signum := ctx.Int("signal")
	if ctx.IsSet("signal") && signum <= 0 {
		return errs.InvalidFlagValue(ctx, "signal", strconv.Itoa(signum), "")
	}

	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return errors.Wrap(err, "error loading certificates")
	}
	if len(cert.Certificate) == 0 {
		return errors.New("error loading certificate: certificate chain is empty")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "error parsing certificate")
	}
	if leaf.NotAfter.Before(time.Now()) {
		return errors.New("cannot renew an expired certificate")
	}

	renewer, err := newRenewer(caURL, crtFile, keyFile, rootFile)
	if err != nil {
		return err
	}

	afterRenew := getAfterRenewFunc(pid, signum)
	if ctx.Bool("daemon") {
		// Force is always enabled when daemon mode is used
		ctx.Set("force", "true")
		next := nextRenewDuration(leaf, expiresIn)
		return renewer.Daemon(outFile, next, expiresIn, afterRenew)
	}

	// Do not renew if (now - cert.notAfter) > (expiresIn + jitter)
	if expiresIn > 0 {
		jitter := rand.Int63n(int64(expiresIn / 20))
		if d := leaf.NotAfter.Sub(time.Now()); d > expiresIn+time.Duration(jitter) {
			ui.Printf("certificate not renewed: expires in %s\n", d.Round(time.Second))
			return nil
		}
	}

	if _, err := renewer.Renew(outFile); err != nil {
		return err
	}

	ui.Printf("Your certificate has been saved in %s.\n", outFile)
	return afterRenew()
}

func nextRenewDuration(leaf *x509.Certificate, expiresIn time.Duration) time.Duration {
	period := leaf.NotAfter.Sub(leaf.NotBefore)
	if expiresIn == 0 {
		expiresIn = period / 3
	}

	d := leaf.NotAfter.Sub(time.Now()) - expiresIn
	n := rand.Int63n(int64(period / 20))
	d -= time.Duration(n)
	if d < 0 {
		d = 0
	}
	return d
}

func getAfterRenewFunc(pid, signum int) func() error {
	if pid == 0 {
		return func() error { return nil }
	}

	return func() error {
		if err := syscall.Kill(pid, syscall.Signal(signum)); err != nil {
			return errors.Wrapf(err, "kill %d with signal %d failed", pid, signum)
		}
		return nil
	}
}

type renewer struct {
	client    *ca.Client
	transport *http.Transport
	keyFile   string
}

func newRenewer(caURL, crtFile, keyFile, rootFile string) (*renewer, error) {
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "error loading certificates")
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("error loading certificate: certificate chain is empty")
	}

	rootCert, err := pemutil.ReadCertificate(rootFile)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return &renewer{
		client:    client,
		transport: tr,
		keyFile:   keyFile,
	}, nil
}

func (r *renewer) Renew(outFile string) (*api.SignResponse, error) {
	resp, err := r.client.Renew(r.transport)
	if err != nil {
		return nil, errors.Wrap(err, "error renewing certificate")
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return nil, err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return nil, err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)

	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return nil, errs.FileError(err, outFile)
	}

	return resp, nil
}

func (r *renewer) RenewAndPrepareNext(outFile string, expiresIn time.Duration) (time.Duration, error) {
	resp, err := r.Renew(outFile)
	if err != nil {
		return 0, err
	}

	cert, err := tls.LoadX509KeyPair(outFile, r.keyFile)
	if err != nil {
		return 0, errors.Wrap(err, "error loading certificates")
	}
	if len(cert.Certificate) == 0 {
		return 0, errors.New("error loading certificate: certificate chain is empty")
	}

	// Prepare next transport
	r.transport.TLSClientConfig.Certificates = []tls.Certificate{cert}

	// Get next renew duration
	return nextRenewDuration(resp.ServerPEM.Certificate, expiresIn), nil
}

func (r *renewer) Daemon(outFile string, next, expiresIn time.Duration, afterRenew func() error) error {
	// Loggers
	Info := log.New(os.Stdout, "INFO: ", log.LstdFlags)
	Error := log.New(os.Stderr, "ERROR: ", log.LstdFlags)

	// Daemon loop
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGHUP:
				if n, err := r.RenewAndPrepareNext(outFile, expiresIn); err != nil {
					Error.Println(err)
				} else {
					next = n
					Info.Printf("certificate renewed, next in %s", next.Round(time.Second))
				}
			case syscall.SIGINT, syscall.SIGTERM:
				return nil
			}
		case <-time.After(next):
			if n, err := r.RenewAndPrepareNext(outFile, expiresIn); err != nil {
				next = n
				Error.Println(err)
			} else {
				next = n
				Info.Printf("certificate renewed, next in %s", next.Round(time.Second))
			}
		}
	}
}
