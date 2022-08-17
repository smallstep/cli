package webhook

import (
	"errors"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/flags"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/linkedca"
)

func updateCommand() cli.Command {
	return cli.Command{
		Name:   "update",
		Action: cli.ActionFunc(updateAction),
		Usage:  "update a webhook attached to a provisioner",
		UsageText: `**step ca provisioner webhook update** <name> **--provisioner**=<name>
[**--url**=<url>] [**--kind**=<kind>] [**--bearer-token**=<token>]
[**--basic-auth-username**=<username>] [**--basic-auth-password**=<password>]
[**--disable-tls-client-auth**]
[**--admin-cert**=<file>] [**--admin-key**=<file>] [**--admin-provisioner**=<name>]
[**--admin-subject**=<subject>] [**--password-file**=<file>] [**--ca-url**=<uri>]
[**--root**=<file>] [**--context**=<name>] [**--ca-config**=<file>]`,
		Flags: []cli.Flag{
			// General webhook flags
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
		Description: `**step ca provisioner webhook update** updates a webhook attached to a provisioner.

## POSITIONAL ARGUMENTS

<name>
: The name of the webhook.

## EXAMPLES

Change a webhook's url:
'''
step ca provisioner webhook update my_webhook --provisioner my_provisioner --url https://example.com
'''

Configure a webhook to send a bearer token to the server:
'''
step ca provisioner webhook update my_webhook --provisioner my_provisioner --bearer-token abc123xyz
'''

Change the password sent to the webhook with basic authentication:
'''
step ca provisioner webhook update my_webhook --provisioner my_provisioner --basic-auth-password my_pass
'''

Configure the webhook to be called only when signing x509 certificates, not SSH certificates:
'''
step ca provisioner webhook update my_webhook --provisioner my_provisioner --cert-type X509
'''
`,
	}
}

func updateAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()

	provisionerName := ctx.String("provisioner")

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
		if pwh.Name == args.Get(0) {
			wh = pwh
			break
		}
	}
	if wh == nil {
		return errors.New("provisioner does not have a webhook with that name")
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

	if ctx.IsSet("bearer-token") {
		wh.Auth = &linkedca.Webhook_BearerToken{
			BearerToken: &linkedca.BearerToken{
				BearerToken: ctx.String("bearer-token"),
			},
		}
	} else if ctx.IsSet("basic-auth-username") || ctx.IsSet("basic-auth-password") {
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
		if ctx.IsSet("basic-auth-password") {
			wba.BasicAuth.Password = ctx.String("basic-auth-password")
		}
		wh.Auth = wba
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
	}

	if _, err = client.UpdateProvisionerWebhook(provisionerName, wh); err != nil {
		return err
	}

	return nil
}
