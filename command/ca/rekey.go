package ca

import (
	"encoding/pem"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"math/rand"
	"strconv"
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


	// Do not renew if (cert.notAfter - now) > (expiresIn + jitter)
	if expiresIn > 0 {
		jitter := rand.Int63n(int64(expiresIn / 20))
		if d := time.Until(leaf.NotAfter); d > expiresIn+time.Duration(jitter) {
			ui.Printf("certificate not renewed: expires in %s\n", d.Round(time.Second))
			return nil
		}
	}

	if _, err := renewer.Rekey(outFile); err != nil {
		return err
	}

	ui.Printf("Your certificate has been saved in %s.\n", outFile)



	return nil
}
func (r *renewer) Rekey(outFile string) (*api.SignResponse, error) {
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