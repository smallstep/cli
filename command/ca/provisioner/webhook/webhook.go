package webhook

import (
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/ui"
	"go.step.sm/linkedca"

	"github.com/smallstep/cli/utils/cautils"
)

// Command returns the webhook subcommand.
func Command() cli.Command {
	return cli.Command{
		Name:      "webhook",
		Usage:     "create and manage webhooks for a provisioner",
		UsageText: "step ca provisioner webhook <subcommand> [arguments] [global-flags] [subcommand-flags]",
		Subcommands: cli.Commands{
			addCommand(),
			updateCommand(),
			removeCommand(),
		},
		Description: `**step ca provisioner webhook** command group provides facilities for managing the webhooks attached to a provisioner

Administrators can attach webhooks to provisioners to retrieve additional data that will be available when rendering certificate templates.
Webhooks can also be used to disallow signing certificates for unknown entities.

Any data returned from the webhook server will be added to the template context under the path "Webhooks.<name>".
Implementations of webhook servers must conform to the step-ca documentation at https://smallstep.com/docs/step-ca/templates for parsing and verifying request bodies and forming valid response bodies.

## EXAMPLES

Add a new webhook to a provisioner:
'''
step ca provisioner webhook add my_provisioner my_webhook --url https://example.com
'''

Change a webhook's url:
'''
step ca provisioner webhook update my_provisioner my_webhook --url https://example.com
'''

Remove a webhook:
'''
step ca provisioner webhook remove my_provisioner my_webhook
'''
		`,
	}
}

var (
	urlFlag = cli.StringFlag{
		Name:  "url",
		Usage: `The url of the webhook server.`,
	}
	kindFlag = cli.StringFlag{
		Name:  "kind",
		Usage: `The kind of webhook. Default is ENRICHING.`,
	}
	bearerTokenFileFlag = cli.StringFlag{
		Name:  "bearer-token-file",
		Usage: `The token to be set in the Authorization header of the request to the webhook server.`,
	}
	basicAuthUsernameFlag = cli.StringFlag{
		Name:  "basic-auth-username",
		Usage: `The username portion of the Authorization header of the request to the webhook server when using basic authentication.`,
	}
	basicAuthPasswordFileFlag = cli.StringFlag{
		Name:  "basic-auth-password-file",
		Usage: `The password porition of the Authorization header of the request to the webhook server when using basic authentication.`,
	}
	disableTLSClientAuthFlag = cli.BoolFlag{
		Name:  "disable-tls-client-auth",
		Usage: `The CA will not send a client certificate when requested by the webhook server.`,
	}
	certTypeFlag = cli.StringFlag{
		Name:  "cert-type",
		Usage: `Whether to call this webhook when signing X509 certificates, SSH certificates, or ALL certificates. Default is ALL.`,
	}
)

type crudClient interface {
	GetProvisioner(...ca.ProvisionerOption) (*linkedca.Provisioner, error)
	CreateProvisionerWebhook(provisionerName string, wh *linkedca.Webhook) (*linkedca.Webhook, error)
	UpdateProvisionerWebhook(provisionerName string, wh *linkedca.Webhook) (*linkedca.Webhook, error)
	DeleteProvisionerWebhook(provisionerName string, webhookName string) error
}

func newCRUDClient(cliCtx *cli.Context, cfgFile string) (crudClient, error) {
	// os.Stat("") probably returns os.ErrNotExist, but this behavior is
	// undocumented so we'll handle this case separately.
	if cfgFile == "" {
		return cautils.NewAdminClient(cliCtx)
	}

	_, err := os.Stat(cfgFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return cautils.NewAdminClient(cliCtx)
	case err == nil:
		ui.PrintSelected("CA Configuration", cfgFile)
		cfg, err := config.LoadConfiguration(cfgFile)
		if err != nil {
			return nil, fmt.Errorf("error loading configuration: %w", err)
		}
		if cfg.AuthorityConfig.EnableAdmin {
			return cautils.NewAdminClient(cliCtx)
		}
		return nil, errors.New("the admin API must be enabled to use webhooks")
	default:
		return nil, errs.FileError(err, cfgFile)
	}
}
