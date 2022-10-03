package webhook

import (
	"errors"
	"fmt"

	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/linkedca"
)

func addCommand() cli.Command {
	return cli.Command{
		Name:   "add",
		Action: cli.ActionFunc(addAction),
		Usage:  "add a webhook to a provisioner",
		UsageText: `**step ca provisioner webhook add** <name> **--provisioner**=<name>
[**--url**=<url>] [**--kind**=<kind>] [**--bearer-token**=<token>]
[**--basic-auth-username**=<username>] [**--basic-auth-password**=<password>]
[**--disable-tls-client-auth**] [**--cert-type**=<cert-type>]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			provisionerFlag,
			urlFlag,
			kindFlag,
			bearerTokenFlag,
			basicAuthUsernameFlag,
			basicAuthPasswordFlag,
			disableTLSClientAuthFlag,
			certTypeFlag,

			flags.AdminCert,
			flags.AdminKey,
			flags.AdminProvisioner,
			flags.AdminSubject,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
			flags.Context,
			flags.CaConfig,
		},
		Description: `**step ca provisioner webhook add** adds a webhook to a provisioner.

The command will print the webhook ID and secret that must be used to verify all requests from step CA.

## POSITIONAL ARGUMENTS

<name>
: The name of the webhook.

## EXAMPLES

Create a webhook without an Authorization header:
'''
step ca provisioner webhook add my_webhook --provisioner my_provisioner --url https://example.com
'''

Create a webhook with a bearer token:
'''
step ca provisioner webhook add my_webhook --provisioner my_provisioner --url https://example.com --bearer-token abc123xyz
'''

Create a webhook with basic authentication:
'''
step ca provisioner webhook add my_webhook --provisioner my_provisioner --url https://example.com --basic-auth-username user --basic-auth-password pass
'''

Create a webhook that will never send a client certificate to the webhook server:
'''
step ca provisioner webhook add my_webhook --provisioner my_provisioner --url https://example.com --disable-tls-client-auth
'''

Create a webhook that will only be called when signing x509 certificates:
'''
step ca provisioner webhook add my_webhook --provisioner my_provisioner --url https://example.com --cert-type X509
'''
`}
}

func addAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	provisionerName := ctx.String("provisioner")

	args := ctx.Args()

	kind := linkedca.Webhook_Kind(linkedca.Webhook_Kind_value[ctx.String("kind")])
	if kind == linkedca.Webhook_NO_KIND {
		kind = linkedca.Webhook_ENRICHING
	}

	wh := &linkedca.Webhook{
		Name: args.Get(0),
		Url:  ctx.String("url"),
		Kind: kind,
	}

	if ctx.IsSet("bearer-token") {
		wh.Auth = &linkedca.Webhook_BearerToken{
			BearerToken: &linkedca.BearerToken{
				BearerToken: ctx.String("bearer-token"),
			},
		}
	} else if ctx.IsSet("basic-auth-username") || ctx.IsSet("basic-auth-password") {
		wh.Auth = &linkedca.Webhook_BasicAuth{
			BasicAuth: &linkedca.BasicAuth{
				Username: ctx.String("basic-auth-username"),
				Password: ctx.String("basic-auth-password"),
			},
		}
	}

	if ctx.IsSet("disable-tls-client-auth") {
		wh.DisableTlsClientAuth = ctx.Bool("disable-tls-client-auth")
	}

	if ctx.IsSet("cert-type") {
		certType, ok := linkedca.Webhook_CertType_value[ctx.String("cert-type")]
		if !ok {
			return errors.New("invalid cert-type")
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
