package webhook

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/linkedca"

	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add a webhook to a provisioner",
		UsageText: `**step ca provisioner webhook add** <provisioner_name> <webhook_name>
[**--url**=<url>] [**--kind**=<kind>] [**--bearer-token-file**=<filename>]
[**--basic-auth-username**=<username>] [**--basic-auth-password-file**=<filename>]
[**--disable-tls-client-auth**] [**--cert-type**=<cert-type>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-subject**=<subject>]
[**--admin-provisioner**=<name>] [**--admin-password-file**=<file>]
[**--ca-url**=<uri>] [**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
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
		Description: `**step ca provisioner webhook add** adds a webhook to a provisioner.

The command will print the webhook ID and secret that must be used to verify all requests from step CA.

## POSITIONAL ARGUMENTS

<provisioner_name>
: The name of the provisioner.

<webhook_name>
: The name of the webhook.

## EXAMPLES

Create a webhook without an Authorization header:
'''
step ca provisioner webhook add my_provisioner my_webhook --url https://example.com
'''

Create a webhook with a bearer token:
'''
step ca provisioner webhook add my_provisioner my_webhook --url https://example.com --bearer-token-file token.txt
'''

Create a webhook with basic authentication:
'''
step ca provisioner webhook add my_provisioner my_webhook --url https://example.com --basic-auth-username user --basic-auth-password-file pass.txt
'''

Create a webhook that will never send a client certificate to the webhook server:
'''
step ca provisioner webhook add my_provisioner my_webhook --url https://example.com --disable-tls-client-auth
'''

Create a webhook that will only be called when signing x509 certificates:
'''
step ca provisioner webhook add my_provisioner my_webhook --url https://example.com --cert-type X509
'''`,
	}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 2); err != nil {
		return err
	}

	args := ctx.Args()

	provisionerName := args.Get(0)

	kind := linkedca.Webhook_Kind(linkedca.Webhook_Kind_value[ctx.String("kind")])
	if kind == linkedca.Webhook_NO_KIND {
		kind = linkedca.Webhook_ENRICHING
	}

	wh := &linkedca.Webhook{
		Name: args.Get(1),
		Url:  ctx.String("url"),
		Kind: kind,
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
		var password string
		if ctx.IsSet("basic-auth-password-file") {
			password, err = utils.ReadStringPasswordFromFile(ctx.String("basic-auth-password-file"))
			if err != nil {
				return err
			}
		}
		wh.Auth = &linkedca.Webhook_BasicAuth{
			BasicAuth: &linkedca.BasicAuth{
				Username: ctx.String("basic-auth-username"),
				Password: password,
			},
		}
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
	} else {
		wh.CertType = linkedca.Webhook_ALL
	}

	client, err := newCRUDClient(ctx, ctx.String("ca-config"))
	if err != nil {
		return err
	}

	if wh, err = client.CreateProvisionerWebhook(provisionerName, wh); err != nil {
		return err
	}

	fmt.Printf("Webhook ID: %s\nSecret: %s\n", wh.Id, wh.Secret)

	return nil
}
