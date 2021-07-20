package ca

import (
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/urfave/cli"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func rekeyCertificateCommand() cli.Command {
	return cli.Command{
		Name:      "rekey",
		Action:    command.ActionFunc(rekeyCertificateAction),
		Usage:     "rekey a valid certificate",
		UsageText: `**step ca renew** <crt-file> <key-file> 
					[**--out**=<file>]`,
Description:
		`**step ca rekey** command rekeys the given certificate (with a request to the
		certificate authority) and writes the new certificate to disk - either overwriting
		<crt-file> or using a new file when the **--out**=<file> flag is used.

## POSITIONAL ARGUMENTS

<crt-file>
:  The certificate in PEM format that we want to renew.

<key-file>
:  They private key file of the certificate.

## EXAMPLES

Rekey a certificate
'''
$ step ca rekey
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "out,output-file",
				Usage: "The new certificate <file> path. Defaults to overwriting the <crt-file> positional argument",
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
	outKey := ctx.String("key-out")
	isDaemon := ctx.Bool("daemon")
	execCmd := ctx.String("exec")

	outFile := ctx.String("out")
	if len(outFile) == 0 {
		outFile = certFile
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
	pk, err := pemutil.Read(keyFile)
	if _, err := renewer.Rekey(pk,outFile,outKey); err != nil {
		return err
	}

	ui.Printf("Your certificate has been saved in %s.\n", outFile)
	return afterRenew()




	return nil
}