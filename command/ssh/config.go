package ssh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func configCommand() cli.Command {
	return cli.Command{
		Name:      "config",
		Action:    command.ActionFunc(configAction),
		Usage:     "configures ssh to be used with certificates",
		UsageText: `**step ssh config**`,
		Description: `**step ssh config** configures SSH to be used with certificates.

## EXAMPLES

Print the public keys used to verify user certificates:
'''
$ step ssh config --roots
'''

Print the public keys used to verify host certificates:
'''
$ step ssh config --host --roots
'''

Apply configuration templates on the user system:
'''
$ step ssh config
'''

Apply configuration templates on a host:
'''
$ step ssh config --host
'''

Apply configuration templates with custom variables:
'''
$ step ssh config --set User=joe --set Bastion=bastion.example.com
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "host",
				Usage: "Configures a SSH server instead of a client.",
			},
			cli.BoolFlag{
				Name:  "roots",
				Usage: "Prints the public keys used to verify user or host certificates.",
			},
			cli.BoolFlag{
				Name:  "federation",
				Usage: "Prints all the public keys in the federation. These keys are used to verify user or host certificates",
			},
			cli.StringSliceFlag{
				Name:  "set",
				Usage: "The <key=value> used as a variable in the templates. Use the flag multiple times to multiple variables.",
			},
			flags.DryRun,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			flags.CaConfig,
		},
	}
}

type statusCoder interface {
	StatusCode() int
}

func configAction(ctx *cli.Context) (recoverErr error) {
	isHost := ctx.Bool("host")
	isRoots := ctx.Bool("roots")
	isFederation := ctx.Bool("federation")
	sets := ctx.StringSlice("set")

	switch {
	case isRoots && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "federation")
	case isRoots && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "set")
	case isFederation && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "federation", "set")
	}

	client, err := cautils.NewClient(ctx)
	if err != nil {
		return err
	}

	// Prints user or host keys
	if isRoots || isFederation {
		var roots *api.SSHRootsResponse
		if isRoots {
			roots, err = client.SSHRoots()
		} else {
			roots, err = client.SSHFederation()
		}
		if err != nil {
			if e, ok := err.(statusCoder); ok && e.StatusCode() == http.StatusNotFound {
				return errors.New("step certificates is not configured with SSH support")
			}
			return errors.Wrap(err, "error getting ssh public keys")
		}

		var keys []api.SSHPublicKey
		if isHost {
			if len(roots.HostKeys) == 0 {
				return errors.New("step certificates is not configured with an ssh.hostKey")
			}
			keys = roots.HostKeys
		} else {
			if len(roots.UserKeys) == 0 {
				return errors.New("step certificates is not configured with an ssh.userKey")
			}
			keys = roots.UserKeys
		}

		for _, key := range keys {
			fmt.Printf("%s %s\n", key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
		}
		return nil
	}

	data := map[string]string{
		"StepPath": config.StepPath(),
	}
	if len(sets) > 0 {
		for _, s := range sets {
			i := strings.Index(s, "=")
			if i == -1 {
				return errs.InvalidFlagValue(ctx, "set", s, "")
			}
			data[s[:i]] = s[i+1:]
		}
	}

	// Get configuration snippets and files
	req := &api.SSHConfigRequest{
		Data: data,
	}
	if isHost {
		req.Type = provisioner.SSHHostCert
	} else {
		req.Type = provisioner.SSHUserCert
	}

	resp, err := client.SSHConfig(req)
	if err != nil {
		return err
	}

	var templates []api.Template
	if isHost {
		templates = resp.HostTemplates
	} else {
		templates = resp.UserTemplates
	}
	if len(templates) == 0 {
		fmt.Println("No configuration changes were found.")
		return nil
	}

	defer func() {
		if rec := recover(); rec != nil {
			if err, ok := rec.(error); ok {
				recoverErr = err
			} else {
				panic(rec)
			}
		}
		return
	}()

	if ctx.Bool("dry-run") {
		for _, t := range templates {
			ui.Printf("{{ \"%s\" | bold }}\n", config.StepAbs(t.Path))
			fmt.Println(string(t.Content))
		}
		return nil
	}

	for _, t := range templates {
		if err := t.Write(); err != nil {
			return err
		}
		ui.Printf(`{{ "%s" | green }} {{ "%s" | bold }}`+"\n", ui.IconGood, config.StepAbs(t.Path))
	}

	return nil
}
