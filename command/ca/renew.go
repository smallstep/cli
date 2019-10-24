package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
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
**step ca renew** command renews the given certificate (with a request to the
certificate authority) and writes the new certificate to disk - either overwriting
<crt-file> or using a new file when the **--out**=<file> flag is used.

With the **--daemon** flag the command will periodically update the given
certificate. By default, it will renew the certificate before 2/3 of the validity
period of the certificate has elapsed. A random jitter is used to avoid multiple
instances running at the same time. The amount of time between renewal and
certificate expiration can be configured using the **--expires-in** flag, or a
fixed period can be set with the **--renew-period** flag.

The **--daemon** flag can be combined with **--pid**, **--signal**, or **--exec**
to provide certificate reloads on your services.

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
'''

Renew the certificate before 2/3 of the validity has passed:
'''
$ step ca renew --daemon internal.crt internal.key
'''

Renew the certificate before 8 hours and 30m of the expiration time:
'''
$ step ca renew --daemon --expires-in 8h30m internal.crt internal.key
'''

Renew the certificate every 16h:
'''
$ step ca renew --daemon --renew-period 16h internal.crt internal.key
'''

Renew the certificate and reload nginx:
'''
$ step ca renew --daemon --exec "nginx -s reload" internal.crt internal.key
'''

Renew the certificate and convert it to DER:
'''
$ step ca renew --daemon --renew-period 16h \
  --exec "step certificate format --force --out internal.der internal.crt" \
  internal.crt internal.key
'''

Renew a certificate using the offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca renew --offline internal.crt internal.key
'''`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Force,
			flags.Offline,
			flags.Root,
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <crt-file> positional argument",
			},
			cli.StringFlag{
				Name: "expires-in",
				Usage: `The amount of time remaining before certificate expiration,
at which point a renewal should be attempted. The certificate renewal will not
be performed if the time to expiration is greater than the **--expires-in** value.
A random jitter (duration/20) will be added to avoid multiple services hitting the
renew endpoint at the same time. The <duration> is a sequence of decimal numbers,
each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.IntFlag{
				Name: "pid",
				Usage: `The process id to signal after the certificate has been renewed. By default the
the SIGHUP (1) signal will be used, but this can be configured with the **--signal**
flag.`,
			},
			cli.IntFlag{
				Name: "signal",
				Usage: `The signal <number> to send to the selected PID, so it can reload the
configuration and load the new certificate. Default value is SIGHUP (1)`,
				Value: int(syscall.SIGHUP),
			},
			cli.StringFlag{
				Name:  "exec",
				Usage: "The <command> to run after the certificate has been renewed.",
			},
			cli.BoolFlag{
				Name: "daemon",
				Usage: `Run the renew command as a daemon, renewing and overwriting the certificate
periodically. By default the daemon will renew a certificate before 2/3 of the
time to expiration has elapsed. The period can be configured using the
**--renew-period** or **--expires-in** flags.`,
			},
			cli.StringFlag{
				Name: "renew-period",
				Usage: `The period with which to schedule renewals of the certificate in daemon mode.
Requires the **--daemon** flag. The <duration> is a sequence of decimal numbers,
each with optional fraction and a unit suffix, such as "300ms", "1.5h", or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`,
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
	isDaemon := ctx.Bool("daemon")
	execCmd := ctx.String("exec")

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

	var expiresIn, renewPeriod time.Duration
	if s := ctx.String("expires-in"); len(s) > 0 {
		if expiresIn, err = time.ParseDuration(s); err != nil {
			return errs.InvalidFlagValue(ctx, "expires-in", s, "")
		}
	}
	if s := ctx.String("renew-period"); len(s) > 0 {
		if renewPeriod, err = time.ParseDuration(s); err != nil {
			return errs.InvalidFlagValue(ctx, "renew-period", s, "")
		}
	}
	if expiresIn > 0 && renewPeriod > 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "expires-in", "renew-period")
	}
	if renewPeriod > 0 && !isDaemon {
		return errs.RequiredWithFlag(ctx, "renew-period", "daemon")
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
	cvp := leaf.NotAfter.Sub(leaf.NotBefore)
	if renewPeriod > 0 && renewPeriod >= cvp {
		return errors.Errorf("flag '--renew-period' must be within (lower than) the certificate "+
			"validity period; renew-period=%v, cert-validity-period=%v", renewPeriod, cvp)
	}

	renewer, err := newRenewer(ctx, caURL, crtFile, keyFile, rootFile)
	if err != nil {
		return err
	}

	afterRenew := getAfterRenewFunc(pid, signum, execCmd)
	if isDaemon {
		// Force is always enabled when daemon mode is used
		ctx.Set("force", "true")
		next := nextRenewDuration(leaf, expiresIn, renewPeriod)
		return renewer.Daemon(outFile, next, expiresIn, renewPeriod, afterRenew)
	}

	// Do not renew if (cert.notAfter - now) > (expiresIn + jitter)
	if expiresIn > 0 {
		jitter := rand.Int63n(int64(expiresIn / 20))
		if d := time.Until(leaf.NotAfter); d > expiresIn+time.Duration(jitter) {
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

func nextRenewDuration(leaf *x509.Certificate, expiresIn, renewPeriod time.Duration) time.Duration {
	if renewPeriod > 0 {
		// Renew now if it will be expired in renewPeriod
		if (time.Until(leaf.NotAfter) - renewPeriod) <= 0 {
			return 0
		}
		return renewPeriod
	}

	period := leaf.NotAfter.Sub(leaf.NotBefore)
	if expiresIn == 0 {
		expiresIn = period / 3
	}

	d := time.Until(leaf.NotAfter) - expiresIn
	n := rand.Int63n(int64(period / 20))
	d -= time.Duration(n)
	if d < 0 {
		d = 0
	}
	return d
}

func getAfterRenewFunc(pid, signum int, execCmd string) func() error {
	return func() error {
		if err := runKillPid(pid, signum); err != nil {
			return err
		}
		return runExecCmd(execCmd)
	}
}

func runKillPid(pid, signum int) error {
	if pid == 0 {
		return nil
	}
	if err := syscall.Kill(pid, syscall.Signal(signum)); err != nil {
		return errors.Wrapf(err, "kill %d with signal %d failed", pid, signum)
	}
	return nil
}

func runExecCmd(execCmd string) error {
	execCmd = strings.TrimSpace(execCmd)
	if execCmd == "" {
		return nil
	}
	parts := strings.Split(execCmd, " ")
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type renewer struct {
	client    cautils.CaClient
	transport *http.Transport
	keyFile   string
	offline   bool
}

func newRenewer(ctx *cli.Context, caURL, crtFile, keyFile, rootFile string) (*renewer, error) {
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "error loading certificates")
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("error loading certificate: certificate chain is empty")
	}

	rootCAs, err := x509util.ReadCertPool(rootFile)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			RootCAs:                  rootCAs,
			PreferServerCipherSuites: true,
		},
	}

	var client cautils.CaClient
	offline := ctx.Bool("offline")
	if offline {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		client, err = cautils.NewOfflineCA(caConfig)
		if err != nil {
			return nil, err
		}
	} else {
		client, err = ca.NewClient(caURL, ca.WithTransport(tr))
		if err != nil {
			return nil, err
		}
	}

	return &renewer{
		client:    client,
		transport: tr,
		keyFile:   keyFile,
		offline:   offline,
	}, nil
}

func (r *renewer) Renew(outFile string) (*api.SignResponse, error) {
	resp, err := r.client.Renew(r.transport)
	if err != nil {
		return nil, errors.Wrap(err, "error renewing certificate")
	}

	if resp.CertChainPEM == nil || len(resp.CertChainPEM) == 0 {
		resp.CertChainPEM = []api.Certificate{resp.ServerPEM, resp.CaPEM}
	}
	var data []byte
	for _, certPEM := range resp.CertChainPEM {
		pemblk, err := pemutil.Serialize(certPEM.Certificate)
		if err != nil {
			return nil, errors.Wrap(err, "error serializing certificate PEM")
		}
		data = append(data, pem.EncodeToMemory(pemblk)...)
	}
	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return nil, errs.FileError(err, outFile)
	}

	return resp, nil
}

func (r *renewer) RenewAndPrepareNext(outFile string, expiresIn, renewPeriod time.Duration) (time.Duration, error) {
	const durationOnErrors = 1 * time.Minute

	resp, err := r.Renew(outFile)
	if err != nil {
		return durationOnErrors, err
	}

	cert, err := tls.LoadX509KeyPair(outFile, r.keyFile)
	if err != nil {
		return durationOnErrors, errors.Wrap(err, "error loading certificates")
	}
	if len(cert.Certificate) == 0 {
		return durationOnErrors, errors.New("error loading certificate: certificate chain is empty")
	}

	// Prepare next transport
	r.transport.TLSClientConfig.Certificates = []tls.Certificate{cert}

	// Get next renew duration
	return nextRenewDuration(resp.ServerPEM.Certificate, expiresIn, renewPeriod), nil
}

func (r *renewer) Daemon(outFile string, next, expiresIn, renewPeriod time.Duration, afterRenew func() error) error {
	// Loggers
	Info := log.New(os.Stdout, "INFO: ", log.LstdFlags)
	Error := log.New(os.Stderr, "ERROR: ", log.LstdFlags)

	// Daemon loop
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	Info.Printf("first renewal in %s", next.Round(time.Second))
	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGHUP:
				if n, err := r.RenewAndPrepareNext(outFile, expiresIn, renewPeriod); err != nil {
					Error.Println(err)
				} else {
					next = n
					Info.Printf("certificate renewed, next in %s", next.Round(time.Second))
					if err := afterRenew(); err != nil {
						Error.Println(err)
					}
				}
			case syscall.SIGINT, syscall.SIGTERM:
				return nil
			}
		case <-time.After(next):
			if n, err := r.RenewAndPrepareNext(outFile, expiresIn, renewPeriod); err != nil {
				next = n
				Error.Println(err)
			} else {
				next = n
				Info.Printf("certificate renewed, next in %s", next.Round(time.Second))
				if err := afterRenew(); err != nil {
					Error.Println(err)
				}
			}
		}
	}
}
