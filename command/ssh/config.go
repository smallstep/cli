package ssh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/cli-utils/command"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/step"
	"github.com/smallstep/cli-utils/ui"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/internal/sshutil"
	"github.com/smallstep/cli/utils/cautils"
)

func configCommand() cli.Command {
	return cli.Command{
		Name:   "config",
		Action: command.ActionFunc(configAction),
		Usage:  "configures ssh to be used with certificates",
		UsageText: `**step ssh config**
[**--team**=<name>] [**--team-authority**=<sub-domain>] [**--host**]
[**--set**=<key=value>] [**--set-file**=<file>] [**--dry-run**] [**--roots**]
[**--federation**] [**--console**] [**--force**] [**--offline**] [**--ca-config**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>]
[**--authority**=<name>] [**--profile**=<name>]`,
		Description: `**step ssh config** configures SSH to be used with certificates. It also supports
flags to inspect the root certificates used to sign the certificates.

This command uses the templates defined in step-certificates to set up user and
hosts environments.

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
				Usage: `Configures a SSH server instead of a client.`,
			},
			flags.Team,
			flags.TeamAuthority,
			flags.TeamURL,
			cli.BoolFlag{
				Name:  "roots",
				Usage: `Prints the public keys used to verify user or host certificates.`,
			},
			cli.BoolFlag{
				Name: "federation",
				Usage: `Prints all the public keys in the federation. These keys are used to verify
user or host certificates`,
			},
			cli.StringSliceFlag{
				Name: "set",
				Usage: `The <key=value> used as a variable in the templates. Use the flag multiple
times to set multiple variables.`,
			},
			flags.TemplateSetFile,
			flags.Console,
			flags.DryRun,
			flags.Force,
			flags.CaConfig,
			flags.CaURL,
			flags.Root,
			flags.Offline,
			cli.StringFlag{
				Name:  "context",
				Usage: `The <name> of the context for the new authority.`,
			},
			flags.ContextProfile,
			flags.ContextAuthority,
			flags.HiddenNoContext,
		},
	}
}

func configAction(ctx *cli.Context) (recoverErr error) {
	team := ctx.String("team")
	isHost := ctx.Bool("host")
	isRoots := ctx.Bool("roots")
	isFederation := ctx.Bool("federation")
	sets := ctx.StringSlice("set")

	switch {
	case team != "" && isHost:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "host")
	case team != "" && isRoots:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "roots")
	case team != "" && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "federation")
	case team != "" && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "team", "set")
	case isRoots && isFederation:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "federation")
	case isRoots && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "roots", "set")
	case isFederation && len(sets) > 0:
		return errs.IncompatibleFlagWithFlag(ctx, "federation", "set")
	}

	// Bootstrap Authority
	if team != "" {
		teamAuthority := ctx.String("team-authority")
		// Default to the default SSH authority.
		if teamAuthority == "" {
			teamAuthority = "ssh"
		}
		if err := cautils.BootstrapTeamAuthority(ctx, team, teamAuthority); err != nil {
			return err
		}
	} else {
		if err := step.Contexts().Apply(ctx); err != nil {
			return err
		}
	}

	// Prepare retry function
	retryFunc, err := loginOnUnauthorized(ctx)
	if err != nil {
		return err
	}

	// Initialize CA client with login if needed.
	client, err := cautils.NewClient(ctx, ca.WithRetryFunc(retryFunc))
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
			var statusCoder interface {
				StatusCode() int
			}
			if errors.As(err, &statusCoder) && statusCoder.StatusCode() == http.StatusNotFound {
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
		"GOOS":         runtime.GOOS,
		"StepPath":     step.Path(),
		"StepBasePath": step.BasePath(),
	}
	data[templates.SSHTemplateVersionKey] = "v2"
	if step.Contexts().Enabled() {
		data["Context"] = step.Contexts().GetCurrent().Name
	}
	if ctx.Bool("console") {
		data["Console"] = "true"
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

	if !isHost {
		// Try to get the user from a certificate
		if _, ok := data["User"]; !ok {
			agent, err := sshutil.DialAgent()
			if err != nil {
				return err
			}

			var opts []sshutil.AgentOption
			if roots, err := client.SSHRoots(); err == nil && len(roots.UserKeys) > 0 {
				userKeys := make([]ssh.PublicKey, len(roots.UserKeys))
				for i, uk := range roots.UserKeys {
					userKeys[i] = uk.PublicKey
				}
				opts = append(opts, sshutil.WithSignatureKey(userKeys))
			}
			if certs, err := agent.ListCertificates(opts...); err == nil && len(certs) > 0 {
				if p := certs[0].ValidPrincipals; len(p) > 0 {
					data["User"] = p[0]
				}
			}
		}

		// Force a user to have a username
		if _, ok := data["User"]; !ok {
			return errors.New("ssh certificate not found: please run `step ssh login <identity>`")
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

	var tmplts []api.Template
	if isHost {
		tmplts = resp.HostTemplates
	} else {
		tmplts = resp.UserTemplates
	}
	if len(tmplts) == 0 {
		ui.Println("No configuration changes were found.")
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
	}()

	if ctx.Bool("dry-run") {
		for _, t := range tmplts {
			ui.Printf("{{ \"%s\" | bold }}\n", step.Abs(t.Path))
			ui.Println(string(t.Content))
		}
		return nil
	}

	for _, t := range tmplts {
		if err := t.Write(); err != nil {
			return err
		}
		ui.Printf(`{{ "%s" | green }} {{ "%s" | bold }}`+"\n", ui.IconGood, step.Abs(t.Path))
	}

	return nil
}
