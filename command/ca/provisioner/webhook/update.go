package webhook

import (
	"errors"
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/linkedca"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update a webhook attached to a provisioner",
		UsageText: `**step ca provisioner webhook update** <provisioner_name> <webhook_name>
[**--url**=<url>] [**--kind**=<kind>] [**--bearer-token-file**=<filename>]
[**--basic-auth-username**=<username>] [**--basic-auth-password-file**=<filename>]
[**--disable-tls-client-auth**] [**--cert-type**=<cert-type>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			// General webhook flags
			urlFlag,
			kindFlag,
			bearerTokenFileFlag,
			basicAuthUsernameFlag,
			basicAuthPasswordFileFlag,
			disableTLSClientAuthFlag,
			certTypeFlag,

			flags.AdminCert,
			flags.AdminKey,
			flags.AdminSubject,
			flags.AdminProvisioner,
			flags.AdminPasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
			flags.CaConfig,
		},
		Description: `**step ca provisioner webhook update** updates a webhook attached to a provisioner.

## POSITIONAL ARGUMENTS

<provisioner_name>
: The name of the provisioner.

<webhook_name>
: The name of the webhook.

## EXAMPLES

Change a webhook's url:
'''
step ca provisioner webhook update my_provisioner my_webhook --url https://example.com
'''

Configure a webhook to send a bearer token to the server:
'''
step ca provisioner webhook update my_provisioner my_webhook --bearer-token-file token.txt
'''

Change the password sent to the webhook with basic authentication:
'''
step ca provisioner webhook update my_provisioner my_webhook --basic-auth-password-file my_pass.txt
'''

Configure the webhook to be called only when signing x509 certificates, not SSH certificates:
'''
step ca provisioner webhook update my_provisioner my_webhook --cert-type X509
'''`,
	}
}

func updateAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()

	provisionerName := args.Get(0)

	client, err := newCRUDClient(ctx, ctx.String("ca-config"))
	if err != nil {
		return err
	}

	prov, err := client.GetProvisioner(ca.WithProvisionerName(provisionerName))
	if err != nil {
		return err
	}
	var wh *linkedca.Webhook
	for _, pwh := range prov.Webhooks {
		if pwh.Name == args.Get(1) {
			wh = pwh
			break
		}
	}
	if wh == nil {
		return fmt.Errorf("provisioner %q does not have a webhook with the name %q", provisionerName, args.Get(1))
	}

	if ctx.IsSet("kind") {
		kind := linkedca.Webhook_Kind(linkedca.Webhook_Kind_value[ctx.String("kind")])
		if kind == linkedca.Webhook_NO_KIND {
			return errors.New("invalid webhook kind")
		}
		wh.Kind = kind
	}

	if ctx.IsSet("url") {
		wh.Url = ctx.String("url")
	}

	if ctx.IsSet("bearer-token-file") {
		bearerTkn, err := utils.ReadStringPasswordFromFile(ctx.String("bearer-token-file"))
		if err != nil {
			return err
		}
		wh.Auth = &linkedca.Webhook_BearerToken{
			BearerToken: &linkedca.BearerToken{
				BearerToken: bearerTkn,
			},
		}
	} else if ctx.IsSet("basic-auth-username") || ctx.IsSet("basic-auth-password-file") {
		wba, _ := wh.GetAuth().(*linkedca.Webhook_BasicAuth)
		if wba == nil {
			wba = &linkedca.Webhook_BasicAuth{
				BasicAuth: &linkedca.BasicAuth{},
			}
		}
		if wba.BasicAuth == nil {
			wba.BasicAuth = &linkedca.BasicAuth{}
		}

		if ctx.IsSet("basic-auth-username") {
			wba.BasicAuth.Username = ctx.String("basic-auth-username")
		}
		if ctx.IsSet("basic-auth-password-file") {
			password, err := utils.ReadStringPasswordFromFile(ctx.String("basic-auth-password-file"))
			if err != nil {
				return err
			}
			wba.BasicAuth.Password = password
		}
		wh.Auth = wba
	}

	if ctx.IsSet("disable-tls-client-auth") {
		wh.DisableTlsClientAuth = ctx.Bool("disable-tls-client-auth")
	}

	if ctx.IsSet("cert-type") {
		certType, ok := linkedca.Webhook_CertType_value[ctx.String("cert-type")]
		if !ok {
			return errs.InvalidFlagValue(ctx, "cert-type", ctx.String("cert-type"), "ALL, X509, and SSH")
		}
		wh.CertType = linkedca.Webhook_CertType(certType)
	}

	if _, err = client.UpdateProvisionerWebhook(provisionerName, wh); err != nil {
		return err
	}

	return nil
}
