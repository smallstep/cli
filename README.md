# Step CLI

`step` is a zero trust swiss army knife. It’s an easy-to-use and hard-to-misuse
utility for building, operating, and automating systems that use zero trust
technologies like authenticated encryption (X.509, TLS), single sign-on (OAuth
OIDC, SAML), multi-factor authentication (OATH OTP, FIDO U2F), encryption
mechanisms (JSON Web Encryption, NaCl), and verifiable claims (JWT, SAML
assertions).

For more information and docs see [the step website](https://smallstep.com/cli/)
and the [blog post](https://smallstep.com/blog/zero-trust-swiss-army-knife.html)
announcing step.

![Animated terminal showing step in practice](https://smallstep.com/images/blog/2018-08-07-unfurl.gif)

### Table of Contents

- [Installing](#installing)
- [Documentation](#documentation)
- [Examples](#examples)
- [Getting Started with Development](#getting-started-with-development)
- [How To Add A New Command](./command/README.md)
- [Versioning](#versioning)
- [How To Create A New Release](./distribution.md)
- [LICENSE](./LICENSE)
- [CHANGELOG](./CHANGELOG.md)

## Installing

These instructions will install an OS specific version of the `step` binary on
your local machine. To build from source see [getting started with
development](#getting-started-with-development) below.


### Mac OS

Install `step` via [Homebrew](https://brew.sh/):

```
brew install smallstep/smallstep/step
```

Test:

```
step certificate inspect https://smallstep.com
```

### Linux

Download the latest Debian package from [releases](https://github.com/smallstep/cli/releases):

```
wget https://github.com/smallstep/cli/releases/download/X.Y.Z/step_X.Y.Z_amd64.deb
```

Install the Debian package:

```
sudo dpkg -i step_X.Y.Z_amd64.deb
```

Test:

```
step certificate inspect https://smallstep.com
```

## Documentation

Documentation can be found in three places:

1. On the command line with `step help xxx` where `xxx` is the subcommand you are interested in. Ex: `step help crypto jwk`

2. On the web at https://smallstep.com/docs/cli

3. In your browser with `step help --http :8080` and visiting http://localhost:8080

## Examples

### X.509 Certificates

Create a root CA, an intermediate, and a leaf X.509 certificate. Bundle the
leaf with the intermediate for use with TLS:

```
$ step certificate create --profile root-ca \
    "Example Root CA" root-ca.crt root-ca.key
$ step certificate create \
    "Example Intermediate CA 1" intermediate-ca.crt intermediate-ca.key \
    --profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key
$ step certificate create \
    example.com example.com.crt example.com.key \
    --profile leaf --ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key
$ step certificate bundle \
    example.com.crt intermediate-ca.crt example.com-bundle.crt
```

Extract the expiration date from a certificate (requires
[`jq`](https://stedolan.github.io/jq/)):

```
$ step certificate inspect example.com.crt --format json | jq -r .validity.end
$ step certificate inspect https://smallstep.com --format json | jq -r .validity.end
```

### JSON Object Signing & Encryption (JOSE)

Create a [JSON Web Key](https://tools.ietf.org/html/rfc7517) (JWK), add the
public key to a keyset, and sign a [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT):

```
$ step crypto jwk create pub.json key.json
$ cat pub.json | step crypto jwk keyset add keys.json
$ JWT=$(step crypto jwt sign \
    --key key.json \
    --iss "issuer@example.com" \
    --aud "audience@example.com" \
    --sub "subject@example.com" \
    --exp $(date -v+15M +"%s"))
```

Verify your JWT and return the payload:

```
$ echo $JWT | step crypto jwt verify \
    --jwks keys.json --iss "issuer@example.com" --aud "audience@example.com"
```

### Single Sign-On

Login with Google, get an access token, and use it to make a request to
Google's APIs:

```
curl -H"$(step oauth --header)" https://www.googleapis.com/oauth2/v3/userinfo
```

Login with Google and obtain an OAuth OIDC identity token for single sign-on:

```
$ step oauth \
    --provider https://accounts.google.com \
    --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
    --client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
    --bare --oidc
```

Obtain and verify a Google-issued OAuth OIDC identity token:

```
$ step oauth \
    --provider https://accounts.google.com \
    --client-id 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com \
    --client-secret udTrOT3gzrO7W9fDPgZQLfYJ \
    --bare --oidc \
 | step crypto jwt verify \
   --jwks https://www.googleapis.com/oauth2/v3/certs \
   --iss https://accounts.google.com \
   --aud 1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com
```

### Multi-factor Authentication

Generate a [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm)
token and a QR code:

```
$ step crypto otp generate \
    --issuer smallstep.com --account name@smallstep.com \
    --qr smallstep.png > smallstep.totp
```

Scan the QR Code using Google Authenticator, Authy or similar software and use
it to verify the TOTP token:

```
$ step crypto otp verify --secret smallstep.totp
```

## Getting Started with Development

These instructions will get you a copy of the project up and running on your
local machine for development, testing, and contribution purposes.

Please read the [CLI Style Guide](https://github.com/urfave/cli) before
implementing any features or modifying behavior as it contains expectations
surrounding how the CLI should behave.

All changes to behavior *must* be documented in the [CHANGELOG.md](./CHANGELOG.md).

### Prerequisites

To get started with local development, you will need three things:

- Golang installed locally (instructions available
[here](https://golang.org/doc/install).
- dep installed locally (instructions available
[here](https://golang.github.io/dep/docs/installation.html).
- A version of `make` available for usage of the `Makefile`.
- The repository checked out in the appropriate location of your `$GOPATH`.

Ensure you've checked out the repository into the appropriate path inside your
`$GOPATH`. For example, if your `$GOPATH` is set to `~/go`, then you'd check
this repository out at `~/go/src/github.com/smallstep/cli`. You can
learn more about `$GOPATH` in the
[documentation](https://golang.org/doc/code.html#GOPATH).

### Installing Dependencies and Bootstrapping

Once you've cloned the repository to the appropriate location, you will now be
able to install any other dependencies via the `make bootstrap` command.

You should only ever need to run this command once, as it will ensure you have
the right version of `dep` and `gometalinter` installed.

### Building step

To build step, simply run `make build` which will build the cli and place the
binary in the `bin` folder.

### Running Tests and Linting

Now that you've installed any dependencies, you can run the tests and lint the
code base simply by running `make`.

#### Unit Tests

Run the unit tests:

```
make test
```

For a more verbose version of the unit tests:

```
make vtest
```

#### Integration Tests

Run the integration tests:

```
make integration
```

#### And coding style tests

These tests apply the following `Go` linters to verify code style and formatting:

* [deadcode](https://github.com/tsenart/deadcode)
* [gofmt](https://golang.org/cmd/gofmt/)
* [golint](https://github.com/golang/lint/golint)
* [ineffassign](https://github.com/gordonklaus/ineffassign)
* [metalinter](https://github.com/alecthomas/gometalinter)
* [misspell](https://github.com/client9/misspell/cmd/misspell)
* [vet](https://golang.org/cmd/vet/)

```
make lint
```

### Adding and Removing Dependencies

To add any dependency to the repository, simply import it into your code and
then run `dep ensure` which will update the `Gopkg.lock` file. A specific
version of a dependency can be specified by adding it to the `Gopkg.toml` file
and running `dep ensure`.

To remove a dependency, simply remove it from the codebase and any mention of
it in the `Gopkg.toml` file and run `dep ensure` which will remove it from the
`vendor` folder while updating the `Gopkg.lock` file.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/smallstep/cli).


## License

This project is licensed under the MIT License - see the
[LICENSE](./LICENSE) file for details
