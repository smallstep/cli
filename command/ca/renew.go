package ca

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/offline"
	renewerPkg "github.com/smallstep/cli/internal/renewer"
	"github.com/smallstep/cli/utils"
	caclient "github.com/smallstep/cli/utils/cautils/client"
	"github.com/smallstep/cli/utils/sysutils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/ui"
)

func renewCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "renew",
		Action: command.ActionFunc(renewCertificateAction),
		Usage:  "renew a certificate",
		UsageText: `**step ca renew** <crt-file> <key-file>
[**--mtls**] [**--password-file**=<file>] [**--out**=<file>] [**--expires-in**=<duration>]
[**--force**] [**--pid**=<int>] [**--pid-file**=<file>] [**--signal**=<int>]
[**--exec**=<string>] [**--daemon**] [**--renew-period**=<duration>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]`,
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

The renew command uses mTLS (by default) to authenticate to the step-ca API.
However, there are scenarios where mTLS is not an option - step-ca is behind a
proxy or the leaf certificate is not configured to do client authentication. To
circumvent the default mTLS authentication use **--mtls=false** to force a flow that
uses X5C token based authentication.

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

Renew a certificate using the token flow instead of mTLS:
'''
$ step ca renew --mtls=false --force internal.crt internal.key
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
			cli.BoolTFlag{
				Name: "mtls",
				Usage: `Use mTLS to renew a certificate. Use --mtls=false to force the token
authorization flow instead.`,
			},
			flags.CaConfig,
			flags.Force,
			flags.Offline,
			flags.PasswordFile,
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
			cli.StringFlag{
				Name: "pid-file",
				Usage: `The <file> from which to read the process id that will be signaled after the certificate
has been renewed. By default the the SIGHUP (1) signal will be used, but this can be configured with the **--signal**
flag.`,
			},
			flags.Signal,
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
			flags.CaURL,
			flags.Root,
			flags.Context,
		},
	}
}

func renewCertificateAction(ctx *cli.Context) error {
	err := errs.NumberOfArguments(ctx, 2)
	if err != nil {
		return err
	}

	args := ctx.Args()
	certFile := args.Get(0)
	keyFile := args.Get(1)
	passFile := ctx.String("password-file")
	isDaemon := ctx.Bool("daemon")
	execCmd := ctx.String("exec")

	outFile := ctx.String("out")
	if outFile == "" {
		outFile = certFile
	}

	rootFile := ctx.String("root")
	if rootFile == "" {
		rootFile = pki.GetRootCAPath()
	}

	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
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

	if ctx.IsSet("pid") && ctx.IsSet("pid-file") {
		return errs.MutuallyExclusiveFlags(ctx, "pid", "pid-file")
	}
	pid := ctx.Int("pid")
	if ctx.IsSet("pid") && pid <= 0 {
		return errs.InvalidFlagValue(ctx, "pid", strconv.Itoa(pid), "")
	}

	pidFile := ctx.String("pid-file")
	if len(pidFile) > 0 {
		pidB, err := os.ReadFile(pidFile)
		if err != nil {
			return errs.FileError(err, pidFile)
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(pidB)))
		if err != nil {
			return errs.Wrap(err, "error converting %s to integer process id", pidB)
		}
		if pid <= 0 {
			return errs.InvalidFlagValue(ctx, "pid-file", strconv.Itoa(pid), "")
		}
	}

	signum := ctx.Int("signal")
	if ctx.IsSet("signal") && signum <= 0 {
		return errs.InvalidFlagValue(ctx, "signal", strconv.Itoa(signum), "")
	}

	cert, err := tlsLoadX509KeyPair(certFile, keyFile, passFile)
	if err != nil {
		return err
	}

	cvp := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	if renewPeriod > 0 && renewPeriod >= cvp {
		return errors.Errorf("flag '--renew-period' must be within (lower than) the certificate "+
			"validity period; renew-period=%v, cert-validity-period=%v", renewPeriod, cvp)
	}
	if expiresIn > cvp {
		return errors.Errorf("flag '--expires-in' must be within (lower than) the certificate "+
			"validity period; expires-in=%v, cert-validity-period=%v", expiresIn, cvp)
	}

	renewer, err := newRenewer(ctx, caURL, cert, rootFile)
	if err != nil {
		return err
	}

	afterRenew := getAfterRenewFunc(pid, signum, execCmd)
	if isDaemon {
		// Force is always enabled when daemon mode is used
		ctx.Set("force", "true")
		next := utils.NextRenewDuration(cert.Leaf, expiresIn, renewPeriod)
		return renewer.Daemon(outFile, next, expiresIn, renewPeriod, afterRenew)
	}

	// Do not renew if (cert.notAfter - now) > (expiresIn + jitter)
	if expiresIn > 0 {
		jitter := rand.Int63n(int64(expiresIn / 20))
		if d := time.Until(cert.Leaf.NotAfter); d > expiresIn+time.Duration(jitter) {
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
	if err := sysutils.Kill(pid, syscall.Signal(signum)); err != nil {
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

func newRenewer(ctx *cli.Context, caURL string, cert tls.Certificate, rootFile string) (*renewerPkg.Renewer, error) {

	if len(cert.Certificate) == 0 {
		return nil, errors.New("error loading certificate: certificate chain is empty")
	}

	rootCAs, err := x509util.ReadCertPool(rootFile)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			RootCAs:                  rootCAs,
			PreferServerCipherSuites: true,
		},
	}

	if time.Now().Before(cert.Leaf.NotAfter) {
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	var client caclient.CaClient
	isOffline := ctx.Bool("offline")
	if isOffline {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		client, err = offline.New(ctx, caConfig)
		if err != nil {
			return nil, err
		}
	} else {
		client, err = ca.NewClient(caURL, ca.WithTransport(tr))
		if err != nil {
			return nil, err
		}
	}

	u, err := url.Parse(client.GetCaURL())
	if err != nil {
		return nil, errors.Errorf("error parsing CA URL: %s", client.GetCaURL())
	}

	return renewerPkg.New(client, tr, cert.PrivateKey, isOffline, cert, u, ctx.Bool("mtls")), nil
}

func tlsLoadX509KeyPair(certFile, keyFile, passFile string) (tls.Certificate, error) {
	x509Chain, err := pemutil.ReadCertificateBundle(certFile)
	if err != nil {
		return tls.Certificate{}, errs.Wrap(err, "error reading certificate chain")
	}
	x509ChainBytes := make([][]byte, len(x509Chain))
	for i, c := range x509Chain {
		x509ChainBytes[i] = c.Raw
	}

	opts := []pemutil.Options{pemutil.WithFilename(keyFile)}
	if passFile != "" {
		opts = append(opts, pemutil.WithPasswordFile(passFile))
	}
	pk, err := pemutil.Read(keyFile, opts...)
	if err != nil {
		return tls.Certificate{}, errs.Wrap(err, "error parsing private key")
	}

	return tls.Certificate{
		Certificate: x509ChainBytes,
		PrivateKey:  pk,
		Leaf:        x509Chain[0],
	}, nil
}
