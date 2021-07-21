package ca

import (
	"io/ioutil"
	"math/rand"
	//mathRand "math/rand"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
)

func rekeyCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "rekey",
		Action: command.ActionFunc(rekeyCertificateAction),
		Usage:  "rekey a valid certificate",
		UsageText: `**step ca rekey** <crt-file> <key-file>
[**--out-crt**=<file>] [**--out-key**=<file>] [**--private-key**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--password-file**=<file>]
[**--out**=<file>] [**--expires-in**=<duration>] [**--force**]
[**--expires-in**=<duration>] [**--pid**=<int>] [**--pid-file**=<file>]
[**--signal**=<int>] [**--exec**=<string>] [**--daemon**]
[**--renew-period**=<duration>]`,
		Description: `
**step ca rekey** command rekeys the given certificate (with a request to the
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

Rekey a certificate with the configured CA:
'''
$ step ca rekey internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''

Rekey a certificate without overwriting the previous certificate:
'''
$ step ca rekey --out renewed.crt internal.crt internal.key
'''

Rekey a certificate forcing the overwrite of the previous certificate:
'''
$ step ca rekey --force internal.crt internal.key
'''

Rekey a certificate providing the <--ca-url> and <--root> flags:
'''
$ step ca rekey --ca-url https://ca.smallstep.com:9000 \
  --root /path/to/root_ca.crt internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''

Rekey skipped because it was too early:
'''
$ step ca rekey --expires-in 8h internal.crt internal.key
certificate not renewed: expires in 10h52m5s
'''

Rekey the certificate before 2/3 of the validity has passed:
'''
$ step ca rekey --daemon internal.crt internal.key
'''

Rekey the certificate before 8 hours and 30m of the expiration time:
'''
$ step ca rekey --daemon --expires-in 8h30m internal.crt internal.key
'''

Rekey the certificate every 16h:
'''
$ step ca rekey --daemon --renew-period 16h internal.crt internal.key
'''

Rekey the certificate and reload nginx:
'''
$ step ca rekey --daemon --exec "nginx -s reload" internal.crt internal.key
'''

Rekey the certificate and convert it to DER:
'''
$ step ca renew --daemon --renew-period 16h \
  --exec "step certificate format --force --out internal.der internal.crt" \
  internal.crt internal.key
'''

Rekey a certificate using the offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca rekey --offline internal.crt internal.key
'''

Rekey the certificate and write it to specified files:
'''
$ step ca rekey foo.crt foo.key --out-crt internal.crt --out-key internal.key
'''

Rekey the certificate using a given private key:
'''
$ step ca rekey  internal.crt internal.key --private-key foo.key
'''`,
		Flags: []cli.Flag{
			flags.CaConfig,
			flags.CaURL,
			flags.Force,
			flags.Offline,
			flags.PasswordFile,
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
			cli.StringFlag{
				Name: "pid-file",
				Usage: `The <file> from which to read the process id that will be signaled after the certificate
has been renewed. By default the the SIGHUP (1) signal will be used, but this can be configured with the **--signal**
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
			cli.StringFlag{
				Name:  "out-cert",
				Usage: `Write the new rekeyed certificate into a specified new certificate file.`,
			},
			cli.StringFlag{
				Name:  "out-key",
				Usage: `Write the new rekeyed private key into a specified new private key file.`,
			},
			cli.StringFlag{
				Name: "private-key",
				Usage: `Use a given private key to do the rekeying of a certificate and private key pair,
if nothing is passed, default goes to generating a random pair.`,
			},
		},
	}
}

func rekeyCertificateAction(ctx *cli.Context) error {
	err := errs.NumberOfArguments(ctx, 2)
	if err != nil {
		return err
	}

	args := ctx.Args()
	certFile := args.Get(0)
	keyFile := args.Get(1)
	passFile := ctx.String("password-file")
	outKey := ctx.String("out-key")
	isDaemon := ctx.Bool("daemon")
	execCmd := ctx.String("exec")



	outCrt := ctx.String("out-cert")
	if len(outCrt) == 0 {
		outCrt = certFile
	}

	rootFile := ctx.String("root")
	if len(rootFile) == 0 {
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
		pidB, err := ioutil.ReadFile(pidFile)
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
	leaf := cert.Leaf

	if leaf.NotAfter.Before(time.Now()) {
		return errors.New("cannot renew an expired certificate")
	}
	cvp := leaf.NotAfter.Sub(leaf.NotBefore)
	if renewPeriod > 0 && renewPeriod >= cvp {
		return errors.Errorf("flag '--renew-period' must be within (lower than) the certificate "+
			"validity period; renew-period=%v, cert-validity-period=%v", renewPeriod, cvp)
	}

	renewer, err := newRenewer(ctx, caURL, cert, rootFile)
	if err != nil {
		return err
	}

	afterRenew := getAfterRenewFunc(pid, signum, execCmd)
	if isDaemon {
		// Force is always enabled when daemon mode is used
		ctx.Set("force", "true")
		next := nextRenewDuration(leaf, expiresIn, renewPeriod)
		return renewer.Daemon(outCrt, next, expiresIn, renewPeriod, afterRenew)
	}

	// Do not renew if (cert.notAfter - now) > (expiresIn + jitter)
	if expiresIn > 0 {
		jitter := rand.Int63n(int64(expiresIn / 20))
		//jitter := mathRand.Int63n(int64(expiresIn / 20))
		if d := time.Until(leaf.NotAfter); d > expiresIn+time.Duration(jitter) {
			ui.Printf("certificate not renewed: expires in %s\n", d.Round(time.Second))
			return nil
		}
	}
	pk, err := pemutil.Read(keyFile)
	if _, err := renewer.Rekey(pk, outCrt, outKey); err != nil {
		//if _, err := renewer.Renew(outCrt); err != nil {
		return err
	}

	ui.Printf("Your certificate has been saved in %s.\n", outCrt)
	return afterRenew()
}
