package ssh

import (
	"github.com/pkg/errors"
	"github.com/smallstep/cli/command"
	"github.com/urfave/cli"
)

func configCommand() cli.Command {
	return cli.Command{
		Name:      "config",
		Action:    command.ActionFunc(configAction),
		Usage:     "configures ssh and set known_hosts",
		UsageText: `**step ssh config**`,
		Description: `**step ssh config** configures SSH configuration and known hosts to use SSH
certificates provided by step-certificates.`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "host",
				Usage: "Configures a SSH server instead of a client.",
			},
		},
	}
}

func configAction(ctx *cli.Context) error {
	return errors.New("not implemented")
}
