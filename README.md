# Step CLI

[![GitHub release](https://img.shields.io/github/release/smallstep/cli.svg)](https://github.com/smallstep/cli/releases)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-cli.svg)](https://microbadger.com/images/smallstep/step-cli)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/cli)](https://goreportcard.com/report/github.com/smallstep/cli)
[![Build Status](https://travis-ci.com/smallstep/cli.svg?branch=master)](https://travis-ci.com/smallstep/cli)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/cli)](https://cla-assistant.io/smallstep/cli)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/cli.svg?style=social)](https://github.com/smallstep/cli/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

`step` is a toolkit for working with your *public key infrastructure* (PKI). 
It's also the client counterpart to the [`step-ca`](https://github.com/smallstep/certificates) online Certificate Authority (CA).

Here's a quick example, combining `step oauth` and `step crypto` to get and verify the signature of a Google OAuth OIDC token:

![Animated terminal showing step in practice](https://smallstep.com/images/blog/2018-08-07-unfurl.gif)

**Questions? Ask us on [GitHub Discussions](https://github.com/smallstep/certificates/discussions) or [Gitter](https://gitter.im/smallstep/community).**

[Website](https://smallstep.com) |
[Documentation](https://smallstep.com/docs/step-cli) |
[Installation](https://smallstep.com/docs/step-cli/installation) |
[Getting Started](https://smallstep.com/docs/step-cli/basic-crypto-operations) |
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

See our installation docs [here](https://smallstep.com/docs/step-cli/installation).

## Community

* Connect with `step` users on [GitHub Discussions](https://github.com/smallstep/certificates/discussions) or [Gitter](https://gitter.im/smallstep/community)
* [Open an issue](https://github.com/smallstep/cli/issues/new/choose) and tell us what features you'd like to see
* [Follow Smallstep on Twitter](https://twitter.com/smallsteplabs)

## Further Reading

* [Full documentation for `step`](https://smallstep.com/docs/step-cli)
* We have more examples of `step` and `step-ca` in action on [the Smallstep blog](https://smallstep.com/blog).
* If you're new to PKI and X.509 certificates, or you want a refresher on the core concepts, you may enjoy [Everything PKI](https://smallstep.com/blog/everything-pki/).
