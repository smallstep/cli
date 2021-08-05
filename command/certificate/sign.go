package certificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

const customIntermediateTemplate = `{
	"subject": {{ toJson .Subject }},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": {{ .MaxPathLen }}
	}
}`

func signCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: cli.ActionFunc(signAction),
		Usage:  "sign a certificate signing request (CSR)",
		UsageText: `**step certificate sign** <csr_file> <crt_file> <key_file>
[**--profile**=<profile>] [**--template**=<file>]
[**--password-file**=<file>] [**--path-len**=<maximum>]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--bundle**]`,
		Description: `**step certificate sign** generates a signed
certificate from a certificate signing request (CSR).

## POSITIONAL ARGUMENTS

<csr_file>
: The path to a certificate signing request (CSR) to be signed.

<crt_file>
: The path to an issuing certificate.

<key_file>
: The path to a private key for signing the CSR.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Sign a certificate signing request using the leaf profile:
'''
$ step certificate sign leaf.csr issuer.crt issuer.key
# or
$ step certificate sign --profile leaf leaf.csr issuer.crt issuer.key
'''

Sign a CSR and bundle the new certificate with the issuer:
'''
$ step certificate sign --bundle leaf.csr issuer.crt issuer.key
'''

Sign a CSR with custom validity and bundle the new certificate with the issuer:
'''
$ step certificate sign --bundle --not-before -1m --not-after 16h leaf.csr issuer.crt issuer.key
'''

Sign an intermediate ca:
'''
$ step certificate sign --profile intermediate-ca intermediate.csr issuer.crt issuer.key
'''

Sign an intermediate ca that can sign other intermediates; in this example, the
issuer must set the pathLenConstraint at least to 2 or without a limit:
'''
$ step certificate sign --profile intermediate-ca --path-len 1 intermediate.csr issuer.crt issuer.key
'''

Sign a CSR but only use information present in it, it doesn't add any key or
extended key usages if they are not in the CSR.
'''
$ step certificate sign --profile csr test.csr issuer.crt issuer.key
'''

Sign a CSR with only clientAuth as key usage using a template:
'''
$ cat coyote.tpl
{
	"subject": {
		"country": "US",
        "organization": "Coyote Corporation",
        "commonName": "{{ .Subject.CommonName }}"
	},
	"emailAddresses": {{ toJson .Insecure.CR.EmailAddresses }},
	"keyUsage": ["digitalSignature"],
	"extKeyUsage": ["clientAuth"]
}
$ step certificate create --csr coyote@acme.corp coyote.csr coyote.key
$ step certificate sign --template coyote.tpl coyote.csr issuer.crt issuer.key
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "profile",
				Value: profileLeaf,
				Usage: `The certificate profile sets various certificate details such as
  certificate use and expiration. The default profile is 'leaf' which is suitable
  for a client or server using TLS.

: <profile> is a case-sensitive string and must be one of:

    **leaf**
    :  Signs a leaf x.509 certificate suitable for use with TLS.

    **intermediate-ca**
    :  Signs a certificate that can be used to sign additional leaf certificates.

    **csr**
    :  Signs a x.509 certificate without modifying the CSR.`,
			},
			cli.StringFlag{
				Name:  "template",
				Usage: `The certificate template <file>, a JSON representation of the certificate to create.`,
			},
			flags.PasswordFile,
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
			cli.IntFlag{
				Name: "path-len",
				Usage: `The <maximum> path length to set in the pathLenConstraint of an intermediate-ca.
Defaults to 0. If it's set to -1 no path length limit is imposed.`,
				Value: 0,
			},
			cli.BoolFlag{
				Name:  "bundle",
				Usage: `Bundle the new leaf certificate with the signing certificate.`,
			},
		},
	}
}

func signAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	csrFile := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)

	// Parse certificate request
	csr, err := pemutil.ReadCertificateRequest(csrFile)
	if err != nil {
		return err
	}
	if err = csr.CheckSignature(); err != nil {
		return errors.Wrapf(err, "certificate request has invalid signature")
	}

	// Parse issuer and issuer key (at least one should be present)
	issuers, err := pemutil.ReadCertificateBundle(crtFile)
	if err != nil {
		return err
	}
	ops := []pemutil.Options{}
	passFile := ctx.String("password-file")
	if passFile == "" {
		ops = append(ops, pemutil.WithPasswordPrompt(
			fmt.Sprintf("Please enter the password to decrypt %s", keyFile),
			func(s string) ([]byte, error) {
				return ui.PromptPassword(s)
			}))
	} else {
		ops = append(ops, pemutil.WithPasswordFile(passFile))
	}
	key, err := pemutil.Read(keyFile, ops...)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.Errorf("key in %s does not satisfy the crypto.Signer interface", keyFile)
	}
	if err := validateIssuerKey(issuers[0], signer); err != nil {
		return err
	}

	// Profile flag
	profile := ctx.String("profile")
	if profile != profileLeaf && profile != profileIntermediateCA && profile != profileCSR {
		return errs.InvalidFlagValue(ctx, "profile", profile, "leaf, intermediate-ca, csr")
	}

	// Template flag
	templateFile := ctx.String("template")
	if ctx.IsSet("profile") && templateFile != "" {
		return errs.IncompatibleFlagWithFlag(ctx, "profile", "template")
	}

	// Read template if passed. If not use a template depending on the profile.
	var template string
	if templateFile != "" {
		b, err := utils.ReadFile(templateFile)
		if err != nil {
			return err
		}
		template = string(b)
	} else {
		switch profile {
		case profileLeaf:
			template = x509util.DefaultLeafTemplate
		case profileIntermediateCA:
			template = customIntermediateTemplate
		case profileCSR:
			template = x509util.CertificateRequestTemplate
		default:
			return errors.Errorf("unknown profile %s: this is not expected", profile)
		}
	}

	// pathLenConstraint
	maxPathLen := ctx.Int("path-len")
	if -1 > maxPathLen {
		return errs.InvalidFlagValueMsg(ctx, "path-len", strconv.Itoa(maxPathLen), "path-len must be -1 or greater")
	}

	// Make sure the issuer can sign the profile
	if err := validateIssuer(issuers[0], profile, maxPathLen); err != nil {
		return err
	}

	// NotBefore and NotAfter flags.
	notBefore, ok := flags.ParseTimeOrDuration(ctx.String("not-before"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	if notBefore.IsZero() {
		notBefore = time.Now()
	}

	notAfter, ok := flags.ParseTimeOrDuration(ctx.String("not-after"))
	if !ok {
		return errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	if !notAfter.IsZero() && !notBefore.IsZero() && notBefore.After(notAfter) {
		return errs.IncompatibleFlagValues(ctx, "not-before", ctx.String("not-before"), "not-after", ctx.String("not-after"))
	}
	if notAfter.IsZero() {
		if profile == profileIntermediateCA {
			notAfter = notBefore.Add(defaultIntermediateValidity)
		} else {
			notAfter = notBefore.Add(defaultLeafValidity)
		}
	}

	// Create certificate template from csr.
	data := createTemplateData(csr, maxPathLen)
	tpl, err := x509util.NewCertificate(csr, x509util.WithTemplate(template, data))
	if err != nil {
		return err
	}
	certTpl := tpl.GetCertificate()
	certTpl.NotBefore = notBefore
	certTpl.NotAfter = notAfter

	// Sign certificate
	cert, err := x509util.CreateCertificate(certTpl, issuers[0], certTpl.PublicKey, signer)
	if err != nil {
		return err
	}

	// Write certificate
	pubPEMs := []*pem.Block{{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}}
	if ctx.Bool("bundle") {
		for _, iss := range issuers {
			pubPEMs = append(pubPEMs, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: iss.Raw,
			})
		}
	}

	pubBytes := []byte{}
	for _, pp := range pubPEMs {
		pubBytes = append(pubBytes, pem.EncodeToMemory(pp)...)
	}
	fmt.Print(string(pubBytes))

	return nil
}

// validateIssuerKey makes sure the issuer and key matches.
func validateIssuerKey(crt *x509.Certificate, signer crypto.Signer) error {
	switch pub := crt.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return errors.New("private key type does not match issuer public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return errors.New("private key does not match issuer public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("private key type does not match issuer public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return errors.New("private key does not match issuer public key")
		}
	case ed25519.PublicKey:
		priv, ok := signer.(ed25519.PrivateKey)
		if !ok {
			return errors.New("private key type does not match issuer public key type")
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return errors.New("private key does not match issuer public key")
		}
	default:
		return errors.New("unknown public key algorithm")
	}

	return nil
}

// validateIssuer makes sure the issuer can sign the certificate request.
func validateIssuer(crt *x509.Certificate, profile string, maxPathLen int) error {
	if !crt.BasicConstraintsValid || !crt.IsCA {
		return errors.New("issuer certificate is not a certificate authority")
	}
	if crt.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("issuer certificate does not have the keyCertSign usage")
	}

	if profile == profileIntermediateCA {
		if crt.MaxPathLenZero {
			return errors.New("issuer certificate cannot sign an intermediate-ca: pathLenConstraint is 0")
		}
		if crt.MaxPathLen != -1 && (maxPathLen == -1 || maxPathLen >= crt.MaxPathLen) {
			return errors.Errorf("issuer certificate cannot sign an intermediate-ca: pathLenConstraint is %d, want at most %d", crt.MaxPathLen, crt.MaxPathLen-1)
		}
	}

	return nil
}

// createTemplateData create a new template data with subject and sans based on
// the information in the certificate request, and the maxPathLen for
// intermediate certificates.
func createTemplateData(cr *x509.CertificateRequest, maxPathLen int) x509util.TemplateData {
	var sans []string
	sans = append(sans, cr.DNSNames...)
	sans = append(sans, cr.EmailAddresses...)
	for _, v := range cr.IPAddresses {
		sans = append(sans, v.String())
	}
	for _, v := range cr.URIs {
		sans = append(sans, v.String())
	}

	data := x509util.NewTemplateData()
	data.SetCertificateRequest(cr)
	data.Set("MaxPathLen", maxPathLen)
	data.SetSubject(x509util.Subject{
		Country:            cr.Subject.Country,
		Organization:       cr.Subject.Organization,
		OrganizationalUnit: cr.Subject.OrganizationalUnit,
		Locality:           cr.Subject.Locality,
		Province:           cr.Subject.Province,
		StreetAddress:      cr.Subject.StreetAddress,
		PostalCode:         cr.Subject.PostalCode,
		SerialNumber:       cr.Subject.SerialNumber,
		CommonName:         cr.Subject.CommonName,
	})
	data.SetSANs(sans)
	return data
}
