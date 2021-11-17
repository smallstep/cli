package certificate

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/crypto/x509util"
)

const (
	// Supported profiles
	profileLeaf           = "leaf"
	profileSelfSigned     = "self-signed"
	profileIntermediateCA = "intermediate-ca"
	profileRootCA         = "root-ca"
	profileCSR            = "csr" // Used only on sign

	// Default durations
	defaultLeafValidity         = 24 * time.Hour
	defaultSelfSignedValidity   = 24 * time.Hour
	defaultIntermediateValidity = time.Hour * 24 * 365 * 10
	defaultRootValidity         = time.Hour * 24 * 365 * 10
	defaultTemplatevalidity     = 24 * time.Hour
)

func createCommand() cli.Command {
	return cli.Command{
		Name:   "create",
		Action: command.ActionFunc(createAction),
		Usage:  "create a certificate or certificate signing request",
		UsageText: `**step certificate create** <subject> <crt-file> <key-file>
[**--csr**] [**--profile**=<profile>] [**--template**=<file>]
[**--not-before**=<duration>] [**--not-after**=<duration>]
[**--password-file**=<file>] [**--ca**=<issuer-cert>]
[**--ca-key**=<issuer-key>] [**--ca-password-file**=<file>]
[**--san**=<SAN>] [**--bundle**] [**--key**=<file>]
[**--kty**=<type>] [**--curve**=<curve>] [**--size**=<size>]
[**--no-password**] [**--insecure**]`,
		Description: `**step certificate create** generates a certificate or a
certificate signing request (CSR) that can be signed later using 'step
certificate sign' (or some other tool) to produce a certificate.

By default this command creates x.509 certificates or CSRs for use with TLS. If
you need something else, you can customize the output using templates. See **TEMPLATES** below.

## POSITIONAL ARGUMENTS

<subject>
: The subject of the certificate. Typically this is a hostname for services or an email address for people.

<crt_file>
: File to write CRT or CSR to (PEM format)

<key_file>
: File to write private key to (PEM format). This argument is optional if **--key** is passed.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## TEMPLATES

With templates, you can customize the generated certificate or CSR.
Templates are JSON files representing a [certificate](https://pkg.go.dev/go.step.sm/crypto/x509util?tab=doc#Certificate) [1]
or a [certificate request](https://pkg.go.dev/go.step.sm/crypto/x509util?tab=doc#CertificateRequest) [2].
They use Golang's [<text/template>](https://golang.org/pkg/text/template/) package [3] and
[<Sprig>](https://masterminds.github.io/sprig/) functions [4].

Here's the default template used for generating a leaf certificate:
'''
{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}
'''

And this is the default template for a CSR:
'''
{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }}
}
'''

In a custom template, you can change the **subject**, **dnsNames**,
**emailAddresses**, **ipAddresses**, and **uris**, and you can add custom
x.509 **extensions** or set the **signatureAlgorithm**.

For certificate templates, the common extensions **keyUsage**, **extKeyUsage**, and
**basicConstraints** are also represented as JSON fields.

Two variables are available in templates: **.Subject** contains the <subject> argument,
and **.SANs** contains the SANs provided with the **--san** flag.

Both .Subject and .SANs are objects, and they must be converted to JSON to be used in
the template, you can do this using Sprig's **toJson** function. On the .Subject
object you can access the common name string using the template variable
**.Subject.CommonName**. In **EXAMPLES** below, you can see how these
variables are used in a certificate request.

For more information on the template properties and functions see:
'''raw
[1] https://pkg.go.dev/go.step.sm/crypto/x509util?tab=doc#Certificate
[2] https://pkg.go.dev/go.step.sm/crypto/x509util?tab=doc#CertificateRequest
[3] https://golang.org/pkg/text/template/
[4] https://masterminds.github.io/sprig/
'''

## EXAMPLES

Create a CSR and key:

'''
$ step certificate create foo foo.csr foo.key --csr
'''

Create a CSR using an existing private key:

'''
$ step certificate create --csr --key key.priv foo foo.csr
'''

Create a CSR using an existing encrypted private key:

'''
$ step certificate create --csr --key key.priv --password-file key.pass foo foo.csr
'''

Create a CSR and key with custom Subject Alternative Names:

'''
$ step certificate create foo foo.csr foo.key --csr \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a CSR and key - do not encrypt the key when writing to disk:

'''
$ step certificate create foo foo.csr foo.key --csr --no-password --insecure
'''

Create a root certificate and key:

'''
$ step certificate create root-ca root-ca.crt root-ca.key --profile root-ca
'''

Create an intermediate certificate and key:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key
'''

Create a leaf certificate and key:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key
'''

Create a leaf certificate and encrypt the private key:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
   --password-file ./leaf.pass \
   --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key
'''

Create a leaf certificate and decrypt the CA private key:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
   --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key --ca-password-file ./intermediate.pass
'''

Create a leaf certificate and key with custom Subject Alternative Names:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
  --san inter.smallstep.com --san 1.1.1.1 --san ca.smallstep.com
'''

Create a leaf certificate and key with custom validity:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
  --not-before 24h --not-after 2160h
'''

Create a self-signed leaf certificate and key:

'''
$ step certificate create self-signed-leaf.local leaf.crt leaf.key --profile self-signed --subtle
'''

Create a root certificate and key with underlying OKP Ed25519:

'''
$ step certificate create root-ca root-ca.crt root-ca.key --profile root-ca \
  --kty OKP --curve Ed25519
'''

Create an intermediate certificate and key with underlying EC P-256 key pair:

'''
$ step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
  --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key --kty EC --curve P-256
'''

Create a leaf certificate and key with underlying RSA 2048 key pair:

'''
$ step certificate create foo foo.crt foo.key --profile leaf \
  --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key --kty RSA --size 2048
'''

Create a CSR and key with underlying OKP Ed25519:

'''
$ step certificate create foo foo.csr foo.key --csr --kty OKP --curve Ed25519
'''

Create a root certificate using a custom template. The root certificate will
have a path length constraint that allows at least 2 intermediates:
'''
$ cat root.tpl
{
	"subject": {
		"commonName": "Acme Corporation Root CA"
	},
	"issuer": {
		"commonName": "Acme Corporation Root CA"
	},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": 2
	}
}
$ step certificate create --template root.tpl \
  "Acme Corporation Root CA" root_ca.crt root_ca_key
'''

Create an intermediate certificate using the previous root. This intermediate
will be able to sign also new intermediate certificates:
'''
$ cat intermediate.tpl
{
	"subject": {
		"commonName": "Acme Corporation Intermediate CA"
	},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": 1
	}
}
$ step certificate create --template intermediate.tpl \
  --ca root_ca.crt --ca-key root_ca_key \
  "Acme Corporation Intermediate CA" intermediate_ca.crt intermediate_ca_key
'''

Sign a new intermediate using the previous intermediate, now with path
length 0 using the **--profile** flag:
'''
$ step certificate create --profile intermediate-ca \
  --ca intermediate_ca.crt --ca-key intermediate_ca_key \
  "Coyote Corporation" coyote_ca.crt coyote_ca_key
'''

Create a leaf certificate, that is the default profile and bundle it with
the two intermediate certificates and validate it:
'''
$ step certificate create --ca coyote_ca.crt --ca-key coyote_ca_key \
  "coyote@acme.corp" leaf.crt coyote.key
$ cat leaf.crt coyote_ca.crt intermediate_ca.crt > coyote.crt
$ step certificate verify --roots root_ca.crt coyote.crt
'''

Create a certificate request using a template:
'''
$ cat csr.tpl
{
    "subject": {
        "country": "US",
        "organization": "Coyote Corporation",
        "commonName": "{{ .Subject.CommonName }}"
    },
	"sans": {{ toJson .SANs }}
}
$ step certificate create --csr --template csr.tpl --san coyote@acme.corp \
  "Wile E. Coyote" coyote.csr coyote.key
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "csr",
				Usage: `Generate a certificate signing request (CSR) instead of a certificate.`,
			},
			cli.StringFlag{
				Name:  "profile",
				Value: profileLeaf,
				Usage: `The certificate profile sets various certificate details such as
  certificate use and expiration. The default profile is 'leaf' which is suitable
  for a client or server using TLS.

: <profile> is a case-sensitive string and must be one of:

    **leaf**
	:  Generate a leaf x.509 certificate suitable for use with TLS.

    **intermediate-ca**
    :  Generate a certificate that can be used to sign additional leaf certificates.

    **root-ca**
    :  Generate a new self-signed root certificate suitable for use as a root CA.

    **self-signed**
    :  Generate a new self-signed leaf certificate suitable for use with TLS.
	This profile requires the **--subtle** flag because the use of self-signed leaf
	certificates is discouraged unless absolutely necessary.`,
			},
			cli.StringFlag{
				Name:  "template",
				Usage: `The certificate template <file>, a JSON representation of the certificate to create.`,
			},
			cli.StringFlag{
				Name: "password-file",
				Usage: `The <file> to the file containing the password to
encrypt the new private key or decrypt the user submitted private key.`,
			},
			cli.StringFlag{
				Name:  "ca",
				Usage: `The certificate authority used to issue the new certificate (PEM file).`,
			},
			cli.StringFlag{
				Name:  "ca-key",
				Usage: `The certificate authority private key used to sign the new certificate (PEM file).`,
			},
			cli.StringFlag{
				Name: "ca-password-file",
				Usage: `The <file> to the file containing the password to
decrypt the CA private key.`,
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "The <file> of the private key to use instead of creating a new one (PEM file).",
			},
			cli.BoolFlag{
				Name: "no-password",
				Usage: `Do not ask for a password to encrypt the private key.
Sensitive key material will be written to disk unencrypted. This is not
recommended. Requires **--insecure** flag.`,
			},
			cli.StringFlag{
				Name: "not-before",
				Usage: `The <time|duration> set in the NotBefore property of the certificate. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringFlag{
				Name: "not-after",
				Usage: `The <time|duration> set in the NotAfter property of the certificate. If a
<time> is used it is expected to be in RFC 3339 format. If a <duration> is
used, it is a sequence of decimal numbers, each with optional fraction and a
unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns",
"us" (or "µs"), "ms", "s", "m", "h".`,
			},
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add DNS or IP Address Subjective Alternative Names (SANs). Use the '--san'
flag multiple times to configure multiple SANs.`,
			},
			cli.BoolFlag{
				Name: "bundle",
				Usage: `Bundle the new leaf certificate with the signing certificate. This flag requires
the **--ca** flag.`,
			},
			flags.KTY,
			flags.Size,
			flags.Curve,
			flags.Force,
			flags.Subtle,
			cli.BoolFlag{
				Name:   "insecure",
				Hidden: true,
			},
		},
	}
}

func createAction(ctx *cli.Context) error {
	minArg := 2
	if key := ctx.String("key"); key == "" {
		minArg = 3
	}
	if err := errs.MinMaxNumberOfArguments(ctx, minArg, 3); err != nil {
		return err
	}

	insecure := ctx.Bool("insecure")
	noPass := ctx.Bool("no-password")
	if noPass && !insecure {
		return errs.RequiredWithFlag(ctx, "no-password", "insecure")
	}

	subject := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)
	if crtFile == keyFile {
		return errs.EqualArguments(ctx, "<crt-file>", "<key-file>")
	}

	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	if !notAfter.IsZero() && !notBefore.IsZero() && notBefore.After(notAfter) {
		return errs.IncompatibleFlagValues(ctx, "not-before", ctx.String("not-before"), "not-after", ctx.String("not-after"))
	}

	var (
		sans         = ctx.StringSlice("san")
		profile      = ctx.String("profile")
		templateFile = ctx.String("template")
		bundle       = ctx.Bool("bundle")
		subtle       = ctx.Bool("subtle")
	)

	if ctx.IsSet("profile") && templateFile != "" {
		return errs.IncompatibleFlagWithFlag(ctx, "profile", "template")
	}

	// Read template if passed
	var template string
	if templateFile != "" {
		b, err := utils.ReadFile(templateFile)
		if err != nil {
			return err
		}
		template = string(b)
	}

	// Read or generate key pair
	pub, priv, err := parseOrCreateKey(ctx)
	if err != nil {
		return err
	}

	// Create certificate request
	if ctx.Bool("csr") {
		if bundle {
			return errs.IncompatibleFlagWithFlag(ctx, "bundle", "csr")
		}
		if profile != "" && profile != profileLeaf {
			return errs.IncompatibleFlagWithFlag(ctx, "profile", "csr")
		}
		if ctx.IsSet("ca") {
			return errs.IncompatibleFlagWithFlag(ctx, "ca", "csr")
		}
		if ctx.IsSet("ca-key") {
			return errs.IncompatibleFlagWithFlag(ctx, "ca-key", "csr")
		}
		if ctx.IsSet("ca-password-file") {
			return errs.IncompatibleFlagWithFlag(ctx, "ca-password-file", "csr")
		}
		if ctx.IsSet("not-before") {
			return errs.IncompatibleFlagWithFlag(ctx, "not-before", "csr")
		}
		if ctx.IsSet("not-after") {
			return errs.IncompatibleFlagWithFlag(ctx, "not-after", "csr")
		}

		// Use subject as default san
		if len(sans) == 0 {
			sans = append(sans, subject)
		}

		// Use default template if empty
		if template == "" {
			template = x509util.DefaultCertificateRequestTemplate
		}

		// Create certificate request
		data := x509util.CreateTemplateData(subject, sans)
		csr, err := x509util.NewCertificateRequest(priv, x509util.WithTemplate(template, data))
		if err != nil {
			return err
		}
		cr, err := csr.GetCertificateRequest()
		if err != nil {
			return err
		}

		block, err := pemutil.Serialize(cr)
		if err != nil {
			return err
		}

		// Save key and certificate request
		if keyFile != "" {
			if err := savePrivateKey(ctx, keyFile, priv, noPass); err != nil {
				return err
			}
		}

		if err = utils.WriteFile(crtFile, pem.EncodeToMemory(block), 0600); err != nil {
			return errs.FileError(err, crtFile)
		}

		ui.Printf("Your certificate signing request has been saved in %s.\n", crtFile)
		if keyFile != "" {
			ui.Printf("Your private key has been saved in %s.\n", keyFile)
		}

		return nil
	}

	// Bundle is only valid for leaf certificates
	if bundle && profile != profileLeaf {
		return errs.IncompatibleFlagValue(ctx, "bundle", "profile", profile)
	}

	// Subtle is required on self-signed certificates
	if !subtle && profile == profileSelfSigned {
		return errs.RequiredWithFlagValue(ctx, "profile", "self-signed", "subtle")
	}

	// Parse --ca and --ca-key flags and check when those flags are required.
	parent, signer, err := parseSigner(ctx, priv)
	if err != nil {
		return err
	}

	// Use subject as default SAN when using a template or for leaf and self-signed certificates.
	if len(sans) == 0 && (template != "" || profile == profileLeaf || profile == profileSelfSigned) {
		sans = append(sans, subject)
	}

	var defaultValidity time.Duration
	if template == "" {
		switch profile {
		case profileLeaf:
			template = x509util.DefaultLeafTemplate
			defaultValidity = defaultLeafValidity
		case profileIntermediateCA:
			template = x509util.DefaultIntermediateTemplate
			defaultValidity = defaultIntermediateValidity
		case profileRootCA:
			template = x509util.DefaultRootTemplate
			defaultValidity = defaultRootValidity
		case profileSelfSigned:
			template = x509util.DefaultLeafTemplate
			defaultValidity = defaultSelfSignedValidity
		default:
			return errs.InvalidFlagValue(ctx, "profile", profile, "leaf, intermediate-ca, root-ca, self-signed")
		}
	} else {
		defaultValidity = defaultTemplatevalidity
	}

	// Create X.509 certificate used as base for the certificate
	cr, err := x509util.CreateCertificateRequest(subject, sans, signer)
	if err != nil {
		return err
	}

	// Create X.509 certificate
	templateData := x509util.CreateTemplateData(subject, sans)
	certificate, err := x509util.NewCertificate(cr, x509util.WithTemplate(template, templateData))
	if err != nil {
		return err
	}
	certTemplate := certificate.GetCertificate()
	if parent == nil {
		parent = certTemplate
	}

	// Set certificate validity
	certTemplate.NotBefore = notBefore
	certTemplate.NotAfter = notAfter

	if certTemplate.NotBefore.IsZero() {
		certTemplate.NotBefore = time.Now()
	}
	if certTemplate.NotAfter.IsZero() {
		certTemplate.NotAfter = certTemplate.NotBefore.Add(defaultValidity)
	}
	// Check that the certificate is not already expired
	if certTemplate.NotBefore.After(certTemplate.NotAfter) {
		return errors.Errorf("invalid value '%s' for flag '--not-after': certificate is already expired", ctx.String("not-after"))
	}

	cert, err := x509util.CreateCertificate(certTemplate, parent, pub, signer)
	if err != nil {
		return err
	}

	// Serialize certificate
	block, err := pemutil.Serialize(cert)
	if err != nil {
		return err
	}

	pubBytes := pem.EncodeToMemory(block)
	if bundle {
		if block, err = pemutil.Serialize(parent); err != nil {
			return err
		}
		pubBytes = append(pubBytes, pem.EncodeToMemory(block)...)
	}

	// Save key and certificate request
	if keyFile != "" {
		if err := savePrivateKey(ctx, keyFile, priv, noPass); err != nil {
			return err
		}
	}

	if err = utils.WriteFile(crtFile, pubBytes, 0600); err != nil {
		return errs.FileError(err, crtFile)
	}

	ui.Printf("Your certificate has been saved in %s.\n", crtFile)
	if keyFile != "" {
		ui.Printf("Your private key has been saved in %s.\n", keyFile)
	}

	return nil
}

func parseOrCreateKey(ctx *cli.Context) (crypto.PublicKey, crypto.Signer, error) {
	keyFile := ctx.String("key")

	// Validate key parameters and generate key pair
	if keyFile == "" {
		kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, ctx.Bool("insecure"), "kty", "curve", "size")
		if err != nil {
			return nil, nil, err
		}
		pub, priv, err := keys.GenerateKeyPair(kty, crv, size)
		if err != nil {
			return nil, nil, err
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return nil, nil, errors.Errorf("private key of type %T is not a crypto.Signer", priv)
		}
		return pub, signer, nil
	}

	// Validate incompatible flags and read a key file
	switch {
	case ctx.IsSet("kty"):
		return nil, nil, errs.IncompatibleFlag(ctx, "key", "kty")
	case ctx.IsSet("crv"):
		return nil, nil, errs.IncompatibleFlag(ctx, "key", "crv")
	case ctx.IsSet("size"):
		return nil, nil, errs.IncompatibleFlag(ctx, "key", "size")
	}

	ops := []pemutil.Options{}
	passFile := ctx.String("password-file")
	if passFile != "" {
		ops = append(ops, pemutil.WithPasswordFile(passFile))
	}
	v, err := pemutil.Read(keyFile, ops...)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := v.(crypto.Signer)
	if !ok {
		return nil, nil, errors.Errorf("file %s does not contain a valid private key", keyFile)
	}
	return signer.Public(), signer, nil
}

// parseSigner returns the parent certificate and key for leaf and intermediate
// certificates. When a template is used, it will return the key only if the
// flags --ca and --ca-key are passed.
func parseSigner(ctx *cli.Context, defaultSigner crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	var (
		caCert   = ctx.String("ca")
		caKey    = ctx.String("ca-key")
		profile  = ctx.String("profile")
		template = ctx.String("template")
	)

	// Check required flags when profile is used.
	if template == "" {
		switch profile {
		case profileLeaf, profileIntermediateCA:
			if caCert == "" {
				return nil, nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca")
			}
			if caKey == "" {
				return nil, nil, errs.RequiredWithFlagValue(ctx, "profile", profile, "ca-key")
			}
		case profileRootCA, profileSelfSigned:
			if caCert != "" {
				return nil, nil, errs.IncompatibleFlagValue(ctx, "ca", "profile", profile)
			}
			if caKey != "" {
				return nil, nil, errs.IncompatibleFlagValue(ctx, "ca-key", "profile", profile)
			}
		default:
			return nil, nil, errs.InvalidFlagValue(ctx, "profile", profile, "leaf, intermediate-ca, root-ca, self-signed")
		}
	}

	// Root, self-signed, or template with no parent.
	if caCert == "" && caKey == "" {
		return nil, defaultSigner, nil
	}

	// Leaf, intermediate or template with
	switch {
	case caCert != "" && caKey == "":
		return nil, nil, errs.RequiredWithFlag(ctx, "ca", "ca-key")
	case caCert == "" && caKey != "":
		return nil, nil, errs.RequiredWithFlag(ctx, "ca-key", "ca")
	}

	// Parse --ca as a certificate.
	cert, err := pemutil.ReadCertificate(caCert)
	if err != nil {
		return nil, nil, err
	}

	// Parse --ca-key as a crypto.Signer.
	passFile := ctx.String("ca-password-file")
	ops := []pemutil.Options{}
	if passFile != "" {
		ops = append(ops, pemutil.WithPasswordFile(passFile))
	}
	key, err := pemutil.Read(caKey, ops...)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.Errorf("invalid value '%s' for flag '--ca-key': file is not a valid private key", caKey)
	}

	return cert, signer, nil
}

// savePrivateKey saves the given key, asking the password if necessary.
func savePrivateKey(ctx *cli.Context, filename string, priv interface{}, insecure bool) error {
	var err error
	if insecure {
		_, err = pemutil.Serialize(priv, pemutil.ToFile(filename, 0600))
		return err
	}

	var pass []byte
	if passFile := ctx.String("password-file"); passFile != "" {
		pass, err = utils.ReadPasswordFromFile(passFile)
		if err != nil {
			return errors.Wrap(err, "error reading encrypting password from file")
		}
	} else {
		pass, err = ui.PromptPassword("Please enter the password to encrypt the private key",
			ui.WithValidateNotEmpty())
		if err != nil {
			return errors.Wrap(err, "error reading password")
		}
	}
	_, err = pemutil.Serialize(priv, pemutil.WithPassword(pass), pemutil.ToFile(filename, 0600))
	return err
}
