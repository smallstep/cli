package ca

import (
	"crypto"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func rekeyCertificateCommand() cli.Command {
	return cli.Command{
		Name:   "rekey",
		Action: command.ActionFunc(rekeyCertificateAction),
		Usage:  "rekey a certificate",
		UsageText: `**step ca rekey** <crt-file> <key-file>
[**--out-cert**=<file>] [**--out-key**=<file>] [**--private-key**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--password-file**=<file>]
[**--expires-in**=<duration>] [**--force**] [**--exec**=<string>] [**--daemon**]
[**--kty**=<type>] [**--curve**=<curve>] [**--size**=<size>]
[**--expires-in**=<duration>] [**--pid**=<int>] [**--pid-file**=<file>]
[**--signal**=<int>] [**--exec**=<string>] [**--rekey-period**=<duration>]`,
		Description: `
**step ca rekey** command rekeys the given certificate (with a request to the
certificate authority) and writes the new certificate and private key
to disk - either overwriting <crt-file> and <key-file> positional arguments
or using new files when the **--out-cert**=<file> and **--out-key**=<file>
flags are used.

With the **--daemon** flag the command will periodically update the given
certificate. By default, it will rekey the certificate before 2/3 of the validity
period of the certificate has elapsed. A random jitter is used to avoid multiple
instances running at the same time. The amount of time between rekey and
certificate expiration can be configured using the **--expires-in** flag, or a
fixed period can be set with the **--rekey-period** flag.

The **--daemon** flag can be combined with **--pid**, **--signal**, or **--exec**
to provide certificate reloads on your services.

## POSITIONAL ARGUMENTS

<crt-file>
:  The certificate in PEM format that we want to rekey.

<key-file>
:  They key file of the certificate.

## EXAMPLES

Rekey a certificate:
'''
$ step ca rekey internal.crt internal.key
'''

Rekey a certificate without overwriting the existing certificate and key:
'''
$ step ca rekey --out-cert out.crt --out-key out.key internal.crt internal.key
'''

Rekey a certificate forcing the overwrite of the previous certificate and key
(overwrites the existing files without prompting):
'''
$ step ca rekey --force internal.crt internal.key
'''

Rekey a certificate providing the <--ca-url> and <--root> flags:
'''
$ step ca rekey --ca-url https://ca.smallstep.com:9000 \
  --root /path/to/root_ca.crt internal.crt internal.key
Would you like to overwrite internal.crt [Y/n]: y
'''

Rekey a certificate only if it expires within the given time frame:
'''
$ step ca rekey --expires-in 8h internal.crt internal.key
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
$ step ca rekey --daemon --rekey-period 16h internal.crt internal.key
'''

Rekey the certificate and reload nginx:
'''
$ step ca rekey --daemon --exec "nginx -s reload" internal.crt internal.key
'''

Rekey the certificate and convert it to DER:
'''
$ step ca rekey --daemon --rekey-period 16h \
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
$ step ca rekey internal.crt internal.key --out-crt foo.crt --out-key foo.key
'''

Rekey the certificate using a given private key:
'''
$ step ca rekey internal.crt internal.key --private-key foo.key
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "out-cert",
				Usage: `The <file> where the new certificate will be saved to.
Defaults to overwriting the <crt-file> positional argument.`,
			},
			cli.StringFlag{
				Name: "out-key",
				Usage: `The <file> to store the new private key.
Defaults to overwriting the <key-file> positional argument.`,
			},
			cli.StringFlag{
				Name: "private-key",
				Usage: `The <file> containing the private key for rekey-ing the certificate.
By default, a new random key pair will be generated.`,
			},
			cli.StringFlag{
				Name: "expires-in",
				Usage: `The amount of time remaining before certificate expiration,
at which point a rekey should be attempted. The certificate rekey will not
be performed if the time to expiration is greater than the **--expires-in** value.
A random jitter (duration/20) will be added to avoid multiple services hitting the
rekey endpoint at the same time. The <duration> is a sequence of decimal numbers,
each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.IntFlag{
				Name: "pid",
				Usage: `The process id to signal after the certificate has been rekeyed. By default the
the SIGHUP (1) signal will be used, but this can be configured with the **--signal**
flag.`,
			},
			cli.StringFlag{
				Name: "pid-file",
				Usage: `The <file> from which to read the process id that will be signaled after the certificate
has been rekeyed. By default the SIGHUP (1) signal will be used, but this can be configured with the **--signal**
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
				Usage: "The <command> to run after the certificate has been rekeyed.",
			},
			cli.BoolFlag{
				Name: "daemon",
				Usage: `Run the rekey command as a daemon, rekeying and overwriting the certificate
periodically. By default the daemon will rekey a certificate before 2/3 of the
time to expiration has elapsed. The period can be configured using the
**--rekey-period** or **--expires-in** flags.`,
			},
			cli.StringFlag{
				Name: "rekey-period",
				Usage: `The period with which to schedule rekeying of the certificate in daemon mode.
Requires the **--daemon** flag. The <duration> is a sequence of decimal numbers,
each with optional fraction and a unit suffix, such as "300ms", "1.5h", or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`,
			},
			flags.KTY,
			flags.Curve,
			flags.Size,
			flags.Force,
			flags.Offline,
			flags.PasswordFile,
			flags.Root,
			flags.CaURL,
			flags.CaConfig,
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
	isDaemon := ctx.Bool("daemon")
	execCmd := ctx.String("exec")
	givenPrivate := ctx.String("private-key")

	outCert := ctx.String("out-cert")
	if outCert == "" {
		outCert = certFile
	}
	outKey := ctx.String("out-key")
	if outKey == "" {
		outKey = keyFile
	}

	rootFile := ctx.String("root")
	if rootFile == "" {
		rootFile = pki.GetRootCAPath()
	}

	caURL, err := flags.ParseCaURL(ctx)
	if err != nil {
		return err
	}

	var expiresIn, rekeyPeriod time.Duration
	if s := ctx.String("expires-in"); s != "" {
		if expiresIn, err = time.ParseDuration(s); err != nil {
			return errs.InvalidFlagValue(ctx, "expires-in", s, "")
		}
	}
	if s := ctx.String("rekey-period"); s != "" {
		if rekeyPeriod, err = time.ParseDuration(s); err != nil {
			return errs.InvalidFlagValue(ctx, "rekey-period", s, "")
		}
	}
	if expiresIn > 0 && rekeyPeriod > 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "expires-in", "rekey-period")
	}
	if rekeyPeriod > 0 && !isDaemon {
		return errs.RequiredWithFlag(ctx, "rekey-period", "daemon")
	}

	if ctx.IsSet("pid") && ctx.IsSet("pid-file") {
		return errs.MutuallyExclusiveFlags(ctx, "pid", "pid-file")
	}
	pid := ctx.Int("pid")
	if ctx.IsSet("pid") && pid <= 0 {
		return errs.InvalidFlagValue(ctx, "pid", strconv.Itoa(pid), "")
	}

	pidFile := ctx.String("pid-file")
	if pidFile != "" {
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
	leaf := cert.Leaf

	if leaf.NotAfter.Before(time.Now()) {
		return errors.New("cannot rekey an expired certificate")
	}
	cvp := leaf.NotAfter.Sub(leaf.NotBefore)
	if rekeyPeriod > 0 && rekeyPeriod >= cvp {
		return errors.Errorf("flag '--rekey-period' must be within (lower than) the certificate "+
			"validity period; rekey-period=%v, cert-validity-period=%v", rekeyPeriod, cvp)
	}

	renewer, err := newRenewer(ctx, caURL, cert, rootFile)
	if err != nil {
		return err
	}

	afterRekey := getAfterRenewFunc(pid, signum, execCmd)
	if isDaemon {
		// Force is always enabled when daemon mode is used
		ctx.Set("force", "true")
		next := nextRenewDuration(leaf, expiresIn, rekeyPeriod)
		return renewer.Daemon(outCert, next, expiresIn, rekeyPeriod, afterRekey)
	}

	// Do not rekey if (cert.notAfter - now) > (expiresIn + jitter)
	if expiresIn > 0 {
		//nolint:gosec // The random number below is not being used for crypto.
		jitter := rand.Int63n(int64(expiresIn / 20))
		if d := time.Until(leaf.NotAfter); d > expiresIn+time.Duration(jitter) {
			ui.Printf("certificate not rekeyed: expires in %s\n", d.Round(time.Second))
			return nil
		}
	}

	var priv crypto.PrivateKey
	if givenPrivate == "" {
		kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, false, "kty", "curve", "size")
		if err != nil {
			return err
		}
		priv, err = keyutil.GenerateKey(kty, crv, size)
		if err != nil {
			return err
		}
	} else {
		priv, err = pemutil.Read(givenPrivate)
		if err != nil {
			return err
		}
	}
	if _, err := renewer.Rekey(priv, outCert, outKey, ctx.IsSet("out-key") || givenPrivate == ""); err != nil {
		return err
	}

	ui.PrintSelected("Certificate", outCert)
	// The private key will be written out to disk if:
	// 1) no private key was provided
	// 2) a private key was provided but an outfile for the private key was specified as well
	if givenPrivate == "" || ctx.IsSet("out-key") {
		ui.PrintSelected("Private Key", outKey)
	}
	return afterRekey()
}
