package certificate

import (
	"github.com/urfave/cli"
)

func needsRenewalCommand() cli.Command {
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
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	

	return nil
}
