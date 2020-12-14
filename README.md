# Step CLI

[![GitHub release](https://img.shields.io/github/release/smallstep/cli.svg)](https://github.com/smallstep/cli/releases)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-cli.svg)](https://microbadger.com/images/smallstep/step-cli)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/cli)](https://goreportcard.com/report/github.com/smallstep/cli)
[![Build Status](https://travis-ci.com/smallstep/cli.svg?branch=master)](https://travis-ci.com/smallstep/cli)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/cli)](https://cla-assistant.io/smallstep/cli)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/cli.svg?style=social)](https://github.com/smallstep/cli/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

`step` is a toolkit for working with your *public key infrastructure* (PKI). It's also the client counterpart to the [`step-ca`](https://github.com/smallstep/certificates) online Certificate Authority (CA).

Here's a quick example, combining `step oauth` and `step crypto` to get and verify the signature of a Google OAuth OIDC token:

![Animated terminal showing step in practice](https://smallstep.com/images/blog/2018-08-07-unfurl.gif)

**Questions? Ask us on [GitHub Discussions](https://github.com/smallstep/certificates/discussions).**

[Website](https://smallstep.com) |
[Documentation](https://smallstep.com/docs/step-cli) |
[Installation Guide](#installation) |
[Examples](#examples) |
[FAQs](docs/questions.md) |
[Contributor's Guide](./docs/CONTRIBUTING.md)

## Features

Step CLI's command groups illustrate some of its uses:
- [`step certificate`](https://smallstep.com/docs/step-cli/reference/certificate/): Work with X.509 (TLS/HTTPS) certificates.
  - Create, revoke, validate, lint, and bundle X.509 certificates.
  - Install (and remove) X.509 certificates into your system's (and brower's) trust store.
  - Create key pairs (RSA, ECDSA, EdDSA) and certificate signing requests (CSRs)
  - [Sign CSRs](https://smallstep.com/docs/step-cli/reference/certificate/sign/)
  - Create [RFC5280](https://tools.ietf.org/html/rfc5280) and [CA/Browser Forum](https://cabforum.org/baseline-requirements-documents/)-compliant certificates that work for TLS and HTTPS
  - [Create](https://smallstep.com/docs/step-cli/reference/certificate/create/) CA certificates (root and intermediate signing certificates)
  - Create self-signed & CA-signed certificates
  - [Inspect](https://smallstep.com/docs/step-cli/reference/certificate/inspect/) and [lint](https://smallstep.com/docs/step-cli/reference/certificate/lint/) certificates on disk or in use by a remote server
  - [Install root certificates](https://smallstep.com/docs/step-cli/reference/certificate/install/) so your CA is trusted by default (issue development certificates **that [work in browsers](https://smallstep.com/blog/step-v0-8-6-valid-HTTPS-certificates-for-dev-pre-prod.html)**)

- [`step ca`](https://smallstep.com/docs/step-cli/reference/ca/): Set up your own CA, or make requests of any ACMEv2 ([RFC8555](https://tools.ietf.org/html/rfc8555)) CA, including [`step-ca`](https://github.com/smallstep/certificates). ACME is the protocol used by Let's Encrypt to automate the issuance of HTTPS certificates.
  - Initialize an X.509 and/or SSH CA in one command
  - [Authenticate and obtain a certificate](https://smallstep.com/docs/step-cli/reference/ca/certificate/) using any enrollment mechanism supported by [`step-ca`](https://github.com/smallstep/certificates)
  - Securely [distribute root certificates](https://smallstep.com/docs/step-cli/reference/ca/root/) and [bootstrap](https://smallstep.com/docs/step-cli/reference/ca/bootstrap/) PKI relying parties
  - [Renew](https://smallstep.com/docs/step-cli/reference/ca/renew/) and [revoke](https://smallstep.com/docs/step-cli/reference/ca/revoke/) certificates issued by [`step-ca`](https://github.com/smallstep/certificates)
  - [Submit CSRs](https://smallstep.com/docs/step-cli/reference/ca/sign/) to be signed by [`step-ca`](https://github.com/smallstep/certificates)

- [`step crypto`](https://smallstep.com/docs/step-cli/reference/crypto/): A general-purpose crypto toolkit
  - Work with [JWTs](https://jwt.io) ([RFC7519](https://tools.ietf.org/html/rfc7519)) and [other JOSE constructs](https://datatracker.ietf.org/wg/jose/documents/)
    - [Sign](https://smallstep.com/docs/step-cli/reference/crypto/jwt/sign), [verify](https://smallstep.com/docs/step-cli/reference/crypto/jwt/verify), and [inspect](https://smallstep.com/docs/step-cli/reference/crypto/jwt/inspect) JSON Web Tokens (JWTs)
    - [Sign](https://smallstep.com/docs/step-cli/reference/crypto/jws/sign), [verify](https://smallstep.com/docs/step-cli/reference/crypto/jws/verify), and [inspect](https://smallstep.com/docs/step-cli/reference/crypto/jws/inspect/) arbitrary data using JSON Web Signature (JWS)
    - [Encrypt](https://smallstep.com/docs/step-cli/reference/crypto/jwe/encrypt/) and [decrypt](https://smallstep.com/docs/step-cli/reference/crypto/jwe/decrypt/) data and wrap private keys using JSON Web Encryption (JWE)
    - [Create JWKs](https://smallstep.com/docs/step-cli/reference/crypto/jwk/create/) and [manage key sets](https://smallstep.com/docs/step-cli/reference/crypto/jwk/keyset) for use with JWT, JWE, and JWS
  - [Generate and verify](https://smallstep.com/docs/step-cli/reference/crypto/otp/) TOTP tokens for multi-factor authentication (MFA)
  - Work with [NaCl](https://nacl.cr.yp.to/)'s high-speed tools for encryption and
      signing
  - [Apply key derivation functions](https://smallstep.com/docs/step-cli/reference/crypto/kdf/) (KDFs) and [verify passwords](https://smallstep.com/docs/step-cli/reference/crypto/kdf/compare/) using `scrypt`, `bcrypt`, and `argo2`
  - Generate and check [file hashes](https://smallstep.com/docs/step-cli/reference/crypto/hash/)
- [`step oauth`](https://smallstep.com/docs/step-cli/reference/oauth/): Add an OAuth 2.0 single sign-on flow to any CLI application.
  - Supports OAuth authorization code, out-of-band (OOB), JWT bearer, and refresh token flows
  - Get OAuth access tokens and OIDC identity tokens at the command line from any provider.
  - Verify OIDC identity tokens (`step crypto jwt verify`)
- [`step ssh`](https://smallstep.com/docs/step-cli/reference/ssh/): Create and manage SSH certificates (requires an online or offline [`step-ca`](https://github.com/smallstep/certificates) instance)
  - Generate SSH user and host key pairs and short-lived certificates
  - Add and remove certificates to the SSH agent
  - Inspect SSH certificates
  - Login and use [single sign-on SSH](https://smallstep.com/blog/diy-single-sign-on-for-ssh/)

## Installation

These instructions will install the `step` binary on your local machine. To build from source, see [getting started with development](docs/local-development.md).

### macOS

Install `step` via [Homebrew](https://brew.sh/):

````
$ brew install step
````

### Debian Linux

Download and install the Debian package from our [latest release](https://github.com/smallstep/cli/releases/latest):

```
$ wget https://github.com/smallstep/cli/releases/download/vX.Y.Z/step-cli_X.Y.Z_amd64.deb
$ sudo dpkg -i step-cli_X.Y.Z_amd64.deb
```

### Arch Linux

We are using the [Arch User Repository](https://aur.archlinux.org) to distribute
`step` binaries for Arch Linux.

* The `step-cli` binary tarball can be found [here](https://aur.archlinux.org/packages/step-cli-bin/).
* The `step-ca` binary tarball (for [step certificates](https://github.com/smallstep/certificates) -
a sibling repository) can be found [here](https://aur.archlinux.org/packages/step-ca-bin/).

You can use [yay](https://github.com/Jguer/yay) or [pacman](https://www.archlinux.org/pacman/) to install the packages.

```
$ yay -S step-cli-bin step-ca-bin
```

### Linux (other)

We have `amd64`, `arm64`, and `armv7` releases available to download from our [latest release](https://github.com/smallstep/cli/releases/latest).

## Testing your installation

```
$ step certificate inspect https://smallstep.com
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 326381749415081530968054238478851085504954 (0x3bf265673332db2d0c70e48a163fb7d11ba)
    Signature Algorithm: SHA256-RSA
        Issuer: C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
        Validity
            Not Before: Feb 8 13:07:44 2019 UTC
            Not After : May 9 13:07:44 2019 UTC
        Subject: CN=smallstep.com
[...]
```

## Examples

### Work with X.509 Certificates from `step-ca`

This example assumes you already have [`step-ca`](https://github.com/smallstep/certificates) running at `https://ca.local`.

Get your root certificate fingerprint (run this on the `step-ca` server):

```
$ step certificate fingerprint $(step path)/certs/root_ca.crt
0eea955785796f0a103637df88f29d8dfc8c1f4260f35c8e744be155f06fd82d
```

On a new machine, connect to `step-ca` and configure your local CA client:

```
$ step ca bootstrap --ca-url https://ca.local \
                    --fingerprint 0eea955785796f0a103637df88f29d8dfc8c1f4260f35c8e744be155f06fd82d
```

Now create a key pair, generate a CSR, and get a certificate from `step-ca`:

```
$ step ca certificate foo.local foo.crt foo.key
Use the arrow keys to navigate: ↓ ↑ → ←
What provisioner key do you want to use?
  ▸ bob@smallstep.com (JWK) [kid: XXX]
✔ Please enter the password to decrypt the provisioner key: ...
✔ CA: https://ca.local
✔ Certificate: foo.crt
✔ Private Key: foo.key
```

Use `step certificate inspect` to check our work:

```
$ step certificate inspect --short foo.crt
X.509v3 TLS Certificate (ECDSA P-256) [Serial: 2982...2760]
  Subject:     foo.local
  Issuer:      Intermediate CA
  Provisioner: bob@smallstep.com [ID: EVct...2B-I]
  Valid from:  2019-08-31T00:14:50Z
          to:  2019-09-01T00:14:50Z
```

Renew a certificate, using the CA's default validity policy:

```
$ step ca renew foo.crt foo.key --force
Your certificate has been saved in foo.crt.
```

Revoke a certificate:

```
$ step ca revoke --cert foo.crt --key foo.key
✔ CA: https://ca.local
Certificate with Serial Number 202784089649824696691681223134769107758 has been revoked.

$ step ca renew foo.crt foo.key --force
error renewing certificate: Unauthorized
```

You can install your root certificate locally:

```
$ step certificate install $(step path)/certs/root_ca.crt
```

Now, all certificates issued by your CA will work in your browser and with tools like `curl`. See [our blog post](https://smallstep.com/blog/step-v0-8-6-valid-HTTPS-certificates-for-dev-pre-prod.html) for more info.

![Browser demo of HTTPS working without warnings](https://smallstep.com/images/blog/2019-02-25-localhost-tls.png)

Alternatively, for internal service-to-service communication, you can [configure your code and infrastructure to trust your root certificate](https://github.com/smallstep/autocert/tree/master/examples/hello-mtls).

### More X.509 Examples

The `step certificate` command group can also be used to create an offline CA and self-signed certificates.

Create a self-signed certificate:

<pre><code><b>$ step certificate create foo.local foo.crt foo.key --profile self-signed --subtle</b>
Your certificate has been saved in foo.crt.
Your private key has been saved in foo.key.</code></pre>

Create a root CA, an intermediate, and a leaf X.509 certificate. Bundle the
leaf with the intermediate for use with TLS:

<pre><code><b>$ step certificate create --profile root-ca \
     "Example Root CA" root-ca.crt root-ca.key</b>
Please enter the password to encrypt the private key:
Your certificate has been saved in root-ca.crt.
Your private key has been saved in root-ca.key.

<b>$ step certificate create \
     "Example Intermediate CA 1" intermediate-ca.crt intermediate-ca.key \
     --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key</b>
Please enter the password to decrypt ./root-ca.key:
Please enter the password to encrypt the private key:
Your certificate has been saved in intermediate-ca.crt.
Your private key has been saved in intermediate-ca.key.

<b>$ step certificate create \
     example.com example.com.crt example.com.key \
     --profile leaf --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key</b>
Please enter the password to decrypt ./intermediate-ca.key:
Please enter the password to encrypt the private key:
Your certificate has been saved in example.com.crt.
Your private key has been saved in example.com.key.

<b>$ step certificate bundle \
     example.com.crt intermediate-ca.crt example.com-bundle.crt</b>
Your certificate has been saved in example.com-bundle.crt.</code></pre>

Extract the expiration date from a certificate (requires
[`jq`](https://stedolan.github.io/jq/)):

<pre><code><b>$ step certificate inspect example.com.crt --format json | jq -r .validity.end</b>
2019-02-28T17:46:16Z

<b>$ step certificate inspect https://smallstep.com --format json | jq -r .validity.end</b>
2019-05-09T13:07:44Z</code></pre>

### Work with JOSE objects (JWK, JWT)

Create a [JSON Web Key](https://tools.ietf.org/html/rfc7517) (JWK), add the
public key to a keyset, and sign a [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT):

<pre><code><b>$ step crypto jwk create pub.json key.json</b>
Please enter the password to encrypt the private JWK:
Your public key has been saved in pub.json.
Your private key has been saved in key.json.

<b>$ cat pub.json | step crypto jwk keyset add keys.json</b>

<b>$ JWT=$(step crypto jwt sign \
    --key key.json \
    --iss "issuer@example.com" \
    --aud "audience@example.com" \
    --sub "subject@example.com" \
    --exp $(date -v+15M +"%s"))</b>
Please enter the password to decrypt key.json:

# Verify your JWT and return the payload:
<b>$ echo $JWT | step crypto jwt verify \
    --jwks keys.json --iss "issuer@example.com" --aud "audience@example.com"</b>
{
  "header": {
    "alg": "ES256",
    "kid": "X6yaHYNyxr-psAqvSNKCWc9oYDetvGdo2n2PSRZjxss",
    "typ": "JWT"
  },
  "payload": {
    "aud": "audience@example.com",
    "exp": 1551290879,
    "iat": 1551289983,
    "iss": "issuer@example.com",
    "nbf": 1551289983,
    "sub": "subject@example.com"
  },
  "signature": "JU7fPGqBJcIfauJHA7KP9Wp292g_G9s4bLMVLyRgEQDpL5faaG-3teJ81_igPz1zP7IjHmz8D6Gigt7kbnlasw"
}</code></pre>

### Single Sign-On OAuth OIDC tokens

Here we'll use `step` to run through an OAuth 2.0 authorization code flow with Google, and obtain an OIDC token. You'll need an OAuth Client ID and Client Secret from [Google Cloud Platform's Credentials](https://console.cloud.google.com/apis/credentials) panel.

Login with Google and obtain an OAuth OIDC identity token for single sign-on:

<pre><code><b>$ step oauth \
    --provider https://accounts.google.com \
    --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
    --client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
    --bare --oidc</b>
Your default web browser has been opened to visit:

https://accounts.google.com/o/oauth2/v2/auth?client_id=[...]

xxx-google-xxx.yyy-oauth-yyy.zzz-token-zzz</code></pre>

That outputs the raw JWT. Now let's decode it and verify its signature:

<pre><code><b>$ step oauth \
     --provider https://accounts.google.com \
     --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
     --client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
     --bare --oidc \
     | step crypto jwt verify \
       --jwks https://www.googleapis.com/oauth2/v3/certs \
       --iss https://accounts.google.com \
       --aud 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com</b>
Your default web browser has been opened to visit:

https://accounts.google.com/o/oauth2/v2/auth?client_id=[...]

{
  "header": {
    "alg": "RS256",
    "kid": "f24d6a1930669cb75f19",
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://accounts.google.com",
    "azp": "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com",
    "aud": "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com",
    "sub": "103209689286000948507",
    "hd": "smallstep.com",
    "email": "name@smallstep.com",
    "email_verified": true,
    "at_hash": "euBvS34BVu0SJQ-EsbBT3A",
    "iat": 1551293134,
    "exp": 1551296734
  },
  "signature": "[...]"
}</code></pre>

### OAuth 2.0 API calls

Here's another flow. Let's use `step` to get a Google bearer token using OAuth 2.0, make an HTTP `Authorization:` header from it, and use `curl` to make a request to Google's APIs:

<pre><code><b>$ curl -H"$(step oauth --header)" https://www.googleapis.com/oauth2/v3/userinfo</b>
Your default web browser has been opened to visit:

https://accounts.google.com/o/oauth2/v2/auth?client_id=1087160488420-AAAAAAAAAAAAAAA.apps.googleusercontent.com&code_challenge=XXXXX

{
  "sub": "AAAAAAAAAAAAA",
  "picture": "https://lh6.googleusercontent.com/photo.jpg",
  "email": "bob@smallstep.com",
  "email_verified": true,
  "hd": "smallstep.com"
}</code></pre>


### Multi-factor Authentication

Generate a [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
token and a QR code:

<pre><code><b>$ step crypto otp generate \
    --issuer smallstep.com --account name@smallstep.com \
    --qr smallstep.png > smallstep.totp</b></code></pre>

Scan the QR Code (`smallstep.png`) using Google Authenticator, Authy or similar
software and use it to verify the TOTP token:

<pre><code><b>$ step crypto otp verify --secret smallstep.totp</b></code></pre>

## Community

* [Connect with `step` users on GitHub Discussions](https://github.com/smallstep/certificates/discussions)
* [Open an issue](https://github.com/smallstep/cli/issues/new/choose) and tell us what features you'd like to see
* [Follow Smallstep on Twitter](https://twitter.com/smallsteplabs)

## Further Reading

* [Full documentation for `step`](https://smallstep.com/docs/step-cli)
* We have more examples of `step` and `step-ca` in action on [the Smallstep blog](https://smallstep.com/blog).
* If you're new to PKI and X.509 certificates, or you want a refresher on the core concepts, you may enjoy [Everything PKI](https://smallstep.com/blog/everything-pki/).
