# Step CLI

`step` is a zero trust swiss army knife. It's an easy-to-use and hard-to-misuse
utility for building, operating, and automating systems that use zero trust
technologies like authenticated encryption (X.509, TLS), single sign-on (OAuth
OIDC, SAML), multi-factor authentication (OATH OTP, FIDO U2F),
encryption mechanisms (JSON Web Encryption, NaCl), and verifiable
claims (JWT, SAML assertions).

[Website](https://smallstep.com) |
[Documentation](https://smallstep.com/docs/cli) |
[Installation Guide](#installation-guide) |
[Examples](#examples) |
[Contribution Guide](./docs/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/release/smallstep/cli.svg)](https://github.com/smallstep/cli/releases)
[![Join the chat at https://gitter.im/smallstep/community](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/smallstep/community)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-cli.svg)](https://microbadger.com/images/smallstep/step-cli)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/cli)](https://goreportcard.com/report/github.com/smallstep/cli)
[![Build Status](https://travis-ci.com/smallstep/cli.svg?branch=master)](https://travis-ci.com/smallstep/cli)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/cli)](https://cla-assistant.io/smallstep/cli)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/cli.svg?style=social)](https://github.com/smallstep/cli/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

![Animated terminal showing step in practice](https://smallstep.com/images/blog/2018-08-07-unfurl.gif)

## Installation Guide

These instructions will install an OS specific version of the `step` binary on
your local machine. To build from source see [getting started with
development](#getting-started-with-development) below.

### Mac OS

Install `step` via [Homebrew](https://brew.sh/):

<pre><code>
<b>$ brew install step</b>
</code></pre>

> Note: If you have installed `step` previously through the `smallstep/smallstep`
> tap you will need to run the following commands before installing:

<pre><code>
<b>$ brew untap smallstep/smallstep</b>
<b>$ brew uninstall step</b>
</code></pre>

### Linux

#### Debian

Download and install the latest Debian package from [releases](https://github.com/smallstep/cli/releases):

<pre><code>
<b>$ wget https://github.com/smallstep/cli/releases/download/X.Y.Z/step_X.Y.Z_amd64.deb</b>

# Install the Debian package:
<b>$ sudo dpkg -i step_X.Y.Z_amd64.deb</b>
</code></pre>

#### Arch Linux

We are using the [Arch User Repository](https://aur.archlinux.org) to distribute
`step` binaries for Arch Linux.

* The `step-cli` can be found [here](https://aur.archlinux.org/packages/step-cli-bin/).
* The `step-ca` ([step certificates](https://github.com/smallstep/certificates) -
a sibling repository) can be found [here](https://aur.archlinux.org/packages/step-cli-bin/).
https://sources.archlinux.org/other/pacman/pacman-5.1.3.tar.gz

You can use [pacman](https://www.archlinux.org/pacman/) to install the packages.

### Test
<pre><code>
<b>$ step certificate inspect https://smallstep.com</b>
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
</code></pre>

## Examples

### X.509 Certificates

Create a root CA, an intermediate, and a leaf X.509 certificate. Bundle the
leaf with the intermediate for use with TLS:

<pre><code>
<b>$ step certificate create --profile root-ca \
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
Your certificate has been saved in example.com-bundle.crt.
</code></pre>

Extract the expiration date from a certificate (requires
[`jq`](https://stedolan.github.io/jq/)):

<pre><code>
<b>$ step certificate inspect example.com.crt --format json | jq -r .validity.end</b>
2019-02-28T17:46:16Z

<b>$ step certificate inspect https://smallstep.com --format json | jq -r .validity.end</b>
2019-05-09T13:07:44Z
</code></pre>

You can install your root certificate locally:

```
$ step certificate install root-ca.crt
```

And issued certificates will work in your browser and with tools like `curl`. See [our blog post](https://smallstep.com/blog/step-v0-8-6-valid-HTTPS-certificates-for-dev-pre-prod.html) for more info.

![Browser demo of HTTPS working without warnings](https://smallstep.com/images/blog/2019-02-25-localhost-tls.png)

Alternatively, for internal service-to-service communication, you can [configure your code and infrastructure to trust your root certificate](https://github.com/smallstep/certificates/tree/master/autocert/examples/hello-mtls).

If you need certificates for your microservices, containers, or other internal services see [step certificates](https://github.com/smallstep/certificates), a sub-project that adds an online certificate authority and automated certificate management tools to `step`.

### JSON Object Signing & Encryption (JOSE)

Create a [JSON Web Key](https://tools.ietf.org/html/rfc7517) (JWK), add the
public key to a keyset, and sign a [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT):

<pre><code>
<b>$ step crypto jwk create pub.json key.json</b>
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
}
</code></pre>

### Single Sign-On

Login with Google, get an access token, and use it to make a request to
Google's APIs:

<pre><code>
<b>$ curl -H"$(step oauth --header)" https://www.googleapis.com/oauth2/v3/userinfo</b>
Your default web browser has been opened to visit:

https://accounts.google.com/o/oauth2/v2/auth?client_id=1087160488420-AAAAAAAAAAAAAAA.apps.googleusercontent.com&code_challenge=XXXXX

{
  "sub": "AAAAAAAAAAAAA",
  "picture": "https://lh6.googleusercontent.com/photo.jpg",
  "email": "bob@smallstep.com",
  "email_verified": true,
  "hd": "smallstep.com"
}
</code></pre>

Login with Google and obtain an OAuth OIDC identity token for single sign-on:

<pre><code>
<b>$ step oauth \
    --provider https://accounts.google.com \
    --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
    --client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
    --bare --oidc</b>
Your default web browser has been opened to visit:

https://accounts.google.com/o/oauth2/v2/auth?client_id=[...]

xxx-google-xxx.yyy-oauth-yyy.zzz-token-zzz
</code></pre>

Obtain and verify a Google-issued OAuth OIDC identity token:

<pre><code>
<b>$ step oauth \
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
}
</code></pre>

### Multi-factor Authentication

Generate a [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
token and a QR code:

<pre><code>
<b>$ step crypto otp generate \
    --issuer smallstep.com --account name@smallstep.com \
    --qr smallstep.png > smallstep.totp</b>
</code></pre>

Scan the QR Code (`smallstep.png`) using Google Authenticator, Authy or similar
software and use it to verify the TOTP token:

<pre><code>
<b>$ step crypto otp verify --secret smallstep.totp</b>
</code></pre>

## Documentation

Documentation can be found in three places:

1. On the command line with `step help xxx` where `xxx` is the subcommand you
   are interested in. Ex: `step help crypto jwk`

2. On the web at https://smallstep.com/docs/cli

3. On your browser by running `step help --http :8080` and visiting
   http://localhost:8080

## The Future

We plan to build more tools that facilitate the use and management of zero trust
networks.

* Tell us what you like and don't like about managing identity in your
network - we're eager to help solve problems in this space.
* Tell us what features you'd like to see - open issues or hit us on
[Twitter](https://twitter.com/smallsteplabs).

## Further Reading

* Check out our [blog](https://smallstep.com/blog).
* Eliminate the pain of managing a PKI with [`step
certificates`](https://github.com/smallstep/certificates) - an online
certificate authority and related tools for secure automated certificate
management, so you can use TLS everywhere.
