package certificate

import (
	"crypto/x509"
	"fmt"
	"github.com/smallstep/cli/errs"
	"io/ioutil"
	"os"
	"time"
)

//func needsRenewalCommand() cli.Command {
funct main() {
	return cli.Command{
		Name:   "needs-renewal",
		Action: cli.ActionFunc(needsRenewalAction),
		Usage:  `Check if a certificate needs to be renewed`,
		UsageText: `**step certificate needs-renewal** <crt_file>  [**--expires-in <duration>]`,
		Description: ``,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "expires-in",
				Usage: `Check if the certificate expires in given time duration`,
			},
			//flags.ServerName,
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		    expiresIn        = ctx.String("expires-in")
		    roots      = ctx.String("roots")
		    serverName = ctx.String("servername")
		    crtFile          = ctx.Args().Get(0)
	        cert             *x509.Certificate
	)


	//verifying cert first
	if addr, isURL, err := trimURL(crtFile); err != nil {
		return err
	} else if isURL {
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			return err
		}
		cert = peerCertificates[0]
		for _, pc := range peerCertificates {
			intermediatePool.AddCert(pc)
		}
	} else {
		crtBytes, err := ioutil.ReadFile(crtFile)
		if err != nil {
			return errs.FileError(err, crtFile)
		}
	}
	if cert == nil {
		return errors.Errorf("%s contains no PEM certificate blocks", crtFile)
	}

    //flag testing
	if expiresIn != "" {
		//var err error

		var remainingTime = time.Until(cert.NotAfter).Minutes()
		var totalValidity = cert.NotAfter.Sub(cert.NotBefore).Minutes()
		var percentUsed = float32((1 - remainingTime/totalValidity) * 100)
		remainingPercent := float32(100-percentUsed)

		//get variable passed in from line
		var passedPercent int
		fmt.Scanln(&passedPercent)

		//replace with passedPercent
		varGiven := float32(10)
		if(remainingPercent > varGiven) {
			os.Exit(0)
		}else if (remainingPercent < varGiven){
			os.Exit(1)
		}else {
			os.Exit(255)
		}
	}

	//can numbers get reused for this part instead of having double?
	var remainingValidity = time.Until(cert.NotAfter).Minutes()
	var totalValidity = cert.NotAfter.Sub(cert.NotBefore).Minutes()
	var percentUsed = float32((1 - remainingValidity/totalValidity) * 100)
	fmt.Printf("Percent Used %s\n", percentUsed)

	//if no flag then it runs this
	if (percentUsed >= 66) {
		os.Exit(0)
	}else if(percentUsed < 66) {
		os.Exit(1)
	}else {
		os.Exit(255)
	}
		return nil
}
