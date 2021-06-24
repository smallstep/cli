package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
	"time"
)

func needsRenewalCommand() cli.Command {
	return cli.Command{
		Name:      "needs-renewal",
		Action:    cli.ActionFunc(needsRenewalAction),
		Usage:     `Check if a certificate needs to be renewed`,
		UsageText: `**step certificate needs-renewal** <crt_file> or <host_name> [**--expires-in <duration>]`,
		Description: `**step certificate needs-renewal** Checks certificate expiration from file or from a host if 
		the certificate is over 66% of its lifetime. If the certificate needs renewal this command will return '0'.
		If the certificate is not far enough into its life, it will return '1'. If validation fails, or if an error occurs, 
		this command will produce a non-zero return value.
## POSITIONAL ARGUMENTS

<crt_file>
: The path to a certificate to validate.

<host_name>
: Address of remote host 

## EXIT CODES

This command returns 0 if needing renewal, or returns 1 if the certificate does not need renewal. It will return 255 if any errors occurred

## EXAMPLES
Check certificate for renewal using custom directory 
'''
$ step certificate needs-renewal ./certificate.crt 
'''
Check if certificate will expire within a given time 
'''
$ step certificate needs-renewal ./certificate.crt --expires-in 1h15m
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "expires-in",
				Usage: `Check if the certificate expires in given time duration`,
			},
			cli.StringFlag{
				Name: "roots",
				Usage: `Root certificate(s) that will be used to verify the
				authenticity of the remote server.`},
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	var (
		crtFile    = ctx.Args().Get(0)
		expiresIn  = ctx.String("expires-in")
		roots      = ctx.String("roots")
		serverName = ctx.String("servername")
		cert       *x509.Certificate
	)

	if addr, isURL, err := trimURL(crtFile); err != nil {
		return err
	} else if isURL {
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			os.Exit(255)
		}
		cert = peerCertificates[0]

	} else {
		crtBytes, err := ioutil.ReadFile(crtFile)
		if err != nil {
			os.Exit(255)
		}

		var (
			block *pem.Block
		)
		// The first certificate PEM in the file is our leaf Certificate.
		// Any certificate after the first is added to the list of Intermediate
		// certificates used for path validation.
		for len(crtBytes) > 0 {
			block, crtBytes = pem.Decode(crtBytes)
			if block == nil {
				os.Exit(255)
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if cert == nil {
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					os.Exit(255)
				}
			}
		}
		if cert == nil {
			os.Exit(255)
		}

	}
	var remainingValidity = time.Until(cert.NotAfter)
	var totalValidity = cert.NotAfter.Sub(cert.NotBefore)
	var percentUsed = (1 - remainingValidity.Minutes()/totalValidity.Minutes()) * 100

	if expiresIn != "" {
		duration, err := time.ParseDuration(expiresIn)

		if err != nil {
			os.Exit(255)
		} else {
			if duration.Minutes() > totalValidity.Minutes() {
				os.Exit(1)
			} else {
				os.Exit(0)
			}
		}

	} else {
		if percentUsed >= 66 {
			os.Exit(0)
		} else if percentUsed < 66 {
			os.Exit(1)
		} else {
			os.Exit(255)
		}
	}

	return nil
}
