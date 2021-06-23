package certificate

import "github.com/urfave/cli"

func needsRenewalCommand() cli.Command {
	return cli.Command{
		Name:   "needs-renewal",
		Action: cli.ActionFunc(verifyAction),
		Usage:  `Check if a certificate needs to be renewed`,
		UsageText: `**step certificate needs-renewal** <crt_file>  [**--expires-in <duration>]`,
		Description: ``,
	}
}
