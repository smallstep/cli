# Changelog

NOTE: Please look to the technical section of the [smallstep blog](https://smallstep.com/tags/technical/)
for all release notes for step cli and certificates.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## TEMPLATE -- do not alter or remove

---

## [x.y.z] - aaaa-bb-cc

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [0.27.4] - 2024-09-13

### Added

- Support for signing and publishing RPM and Deb packages to GCP Artifact Registry (smallstep/cli#1246)

### Changed

- Update Release download URLs for RPM and DEB packages with new file name formats (smallstep/cli#1256)

### Fixed

- Parse crlEntryExtensions in CRLs (smallstep/cli#1262)
- PowerShell 5.1 CLI crashes in Windows 11 (smallstep/cli#1257)

### Notes

- Skipping 0.27.3 to synchronize with smallstep/certificates


## [0.27.2] - 2024-07-18

### Added

- `console` flag to SSH commands (smallstep/cli#1238)
- Upload FreeBSD build to S3 (smallstep/cli#1239)


## [0.27.1] - 2024-07-11

### Fixed

- Broken release process


## [0.27.0] - 2024-07-11

### Changed

- Makefile: install to /usr/local/bin, not /usr/bin (smallstep/cli#1214)

### Fixed

- Set proper JOSE algorithm for Ed25519 keys (smallstep/cli#1208)
- Makefile: usage of install command line flags on MacOS (smallstep/cli#1212)
- Restore operation of '--bundle' flag in certificate inspect (smallstep/cli#1215)
- Fish completion (smallstep/cli#1222)
- Restore operation of inspect CSR from STDIN (smallstep/cli#1232)

### Security


## [0.26.2] - 2024-06-13

### Added

- Options for auth-params and scopes to OIDC token generator (smallstep/cli#1154)
- --kty, --curve, and --size to ssh commands (login, certificate) (smallstep/cli#1156)
- Stdin input for SSH needs-renewal (smallstep/cli#1157)
- Allow users to define certificate comment in SSH agent (smallstep/cli#1158)
- Add OCSP and CRL support to certificate verify (smallstep/cli#1161)


## [0.26.1] - 2024-04-22

### Added

- Ability to output inspected CSR in PEM format (smallstep/cli#1153)

### Fixed

- Allow 'certificate inspect' to parse PEM files containig extraneous data (smallstep/cli#1153)


## [v0.26.0] - 2024-03-27

### Added

- Sending of (an automatically generated) request identifier in the X-Request-Id header (smallstep/cli#1120)

### Changed

- Upgrade certinfo (smallstep/cli#1129)
- Upgrade other dependencies

### Fixed

- OIDC flows failing using Chrome and other Chromium based browsers (smallstep/cli#1136)

### Security

- Upgrade to using cosign v2 for signing artifacts

## [v0.25.2] - 2024-01-19

### Added

- Add support for Nebula certificates using ECDSA P-256 (smallstep/cli#1085)

### Changed

- Upgrade docker image using Debian to Bookworm (smallstep/cli#1080)
- Upgrade dependencies, including go-jose to v3 (smallstep/cli#1086)

## [v0.25.1] - 2023-11-28

### Added

- Add `step crypto rand` command in (smallstep/cli#1054)
- Support for custom TPM device name in `--attestation-uri` flag in (smallstep/cli#1044)

### Changed

- Ignore BOM when reading files in (smallstep/cli#1045)
- Upgraded `truststore` to fix installing certificates on certain Linux systems in (smallstep/cli#1053)

### Fixed

- Scoop and WinGet releases
- Command completion for `zsh` in (smallstep/cli#1055)

## [v0.25.0] - 2023-09-26

### Added

- Add support for provisioner claim `disableSmallstepExtensions`
  (smallstep/cli#986)
- Add support for PowerShell plugins on Windows (smallstep/cli#992)
- Create API token using team slug (smallstep/cli#980)
- Detect OIDC tokens issued by Kubernetes (smallstep/cli#953)
- Add support for Smallstep Managed Endpoint X509 extension
  (smallstep/cli#989)
- Support signing a certificate for a private key that can only be used for 
  encryption with the `--skip-csr-signature` flag in `step certificate create`. 
  Some KMSs restrict key usage to a single type of cryptographic operation. 
  This blocks RSA decryption keys from being used to sign a CSR for their public 
  key. Using the `--skip-csr-signature` flag, the public key is used directly 
  with a certificate template, removing the need for the CSR signature.
- Add all AWS identity document certificates (smallstep/certificates#1510)
- Add SCEP decrypter configuration flags (smallstep/cli#950)
- Add detection of OIDC tokens issued by Kubernetes (smallstep/cli#953)
- Add unversioned release artifacts to build (smallstep/cli#965)

### Changed

- Increase PBKDF2 iterations to 600k (smallstep/cli#949)
- `--kms` flag is no longer used for the CA (signing) key for 
`step certificate create`. It was replaced by the `--ca-kms` flag 
(smallstep/cli#942).
- Hide `step oauth command` on failure (smallstep/cli#993)

### Fixed

- Look for Windows plugins with executable extensions
  (smallstep/certificates#976)
- Fix empty ca.json with invalid template data (smallstep/certificates#1501)
- Fix interactive prompt on docker builds (smallstep/cli#963)
- `step certificate fingerprint` correctly parse PEM files with non-PEM header
  (smallstep/crypto#311)
- `step certificate format` correctly parse PEM files with non-PEM header
  (smallstep/cli#1006)
- Fix TOFU flag in `ca provisioner update` (smallstep/cli#941)
- Make `--team` incompatible with `--fingerprint` and `--ca-url` in 
  `step ca bootstrap (smallstep/cli#1017)

### Remove

- Remove automatic creation of the step path (smallstep/certificates#991)

## [v0.24.4] - 2023-05-11

### Added

- Documentation for fish completion (smallstep/cli#930)
- `--audience` flag to `step api token` (smallstep/cli#927)

### Changed

- Depend on [smallstep/go-attestation](https://github.com/smallstep/go-attestation) instead of [google/go-attestation](https://github.com/google/go-attestation)
- Implementation for parsing CRLs (smallstep/cli#926)

## [v0.24.3] - 2023-04-14

### Added 

- Storing of certificate chain for TPM keys in TPM storage (smallstep/cli#915)

### Changed

- The enrolment URL path used when enrolling with an attestation CA (smallstep/cli#915)

### Fixed 

- Issue with CLI reference not showing curly braces correctly (smallstep/cli#916)
- Word wrapping for `step api token` example (smallstep/cli#917)

## [v0.24.2] - 2023-04-14

### Changed

- Cross-compile Debian docker builds to improve release performance
  (smallstep/cli#911).

### Fixed

- Fix encrypted PKCS#8 keys used on `step crypto key format`
  (smallstep/crypto#216).

## [v0.24.1] - 2023-04-12

### Fixed

- Upgrade certificates version (smallstep/cli#910).

## [v0.24.0] - 2023-04-12

### Added

- Support for ACME device-attest-01 challenge with TPM 2.0 (smallstep/cli#712).
- Build and release cleanups (smallstep/cli#883, smallstep/cli#884,
  smallstep/cli#888, and smallstep/cli#896).
- Release of the smallstep/step-cli:bullseye docker image with CGO and glibc
  support (smallstep/cli#885).
- Support for reload using the HUP signal on the test command `step fileserver`
  (smallstep/cli#891).
- Support for Azure sovereign clouds (smallstep/cli#872).

### Fixed

- Fix the `--insecure` flag when creating RSA keys of less than 2048 bits
  (smallstep/cli#878).
- Fix docs for active revocation (smallstep/cli#889)
- Fix signing of X5C tokens with ECDSA P-384 and P-521 keys.
- Fix 404 links in docs (smallstep/cli#907).
- Linting and cleanup changes (smallstep/cli#904 and smallstep/cli#905).

### Changed

- Use key fingerprints by default for SSH certificates, and add `--certificate`
  flag to print the certificate fingerprint (smallstep/cli#908).

### Removed

- Remove `--hugo` flag in `step help` command (smallstep/cli#898).

## [v0.23.4] - 2023-03-09

### Added

- Support on `step ca token` for signing JWK, X5C and SSHPOP tokens using a KMS
  (smallstep/cli#871).
- debian:bullseye base image (smallstep/cli#861)

### Changed

- `step certificate needs-renewal` will only check the leaf certificate by default.
  To test the full certificate bundle use the `--bundle` flag. (smallstep/cli#873)
- Change how `step help --markdown` works: It now ouputs "REAME.mdx" instead of "index.md"

## [v0.23.3] - 2023-03-01

### Fixed

- Prevent re-use of TCP connections between requests on `step oauth` (smallstep/cli#858).
- Upgrade certinfo with a fix for the YubiKey touch policy information (smallstep/cli#854).
- Upgrade Golang dependencies with reported issues.

## [v0.23.2] - 2023-02-06

### Added

- Added support for extended SANs when creating CSRs (smallstep/crypto#168).
- Added check for empty DNS value in `step ca init` (smallstep/cli#815).

### Changed

- Improved prompts and error messages in `step ca init` (smallstep/cli#827),
  (smallstep/cli#831), (smallstep/cli#839).
- Improved ACME device-attest-01 challenge validation logic (smallstep/cli#837).

### Fixed

- Fixed `step ca provisioner add` when CA is not online (smallstep/cli#833).

## [v0.23.1] - 2023-01-10

### Added

- Add scope parameter in `step oauth` (smallstep/cli#816).

### Changed

- Check for remote configuration API before prompting for admin credentials
  (smallstep/cli809).

### Fixed

- Generation of OTT when signing a CSR with URIs (smallstep/cli#799).
- CA certificates path for SLSE with
  [smallstep/truststore/#16](https://github.com/smallstep/truststore/pull/16)
  (smallstep/cli#818).

## [v0.23.0] - 2022-11-11

### Added

- Added support for configuring ACME device-attest-01 challenges.
- Added support to disable ACME challenges and attestation formats.
- Added support for ACME device-attest-01 challenges with YubiKeys.
- Added support for SUSE13 and upwards for `step certificate install`.
- Added support for printing [Sigstore](https://www.sigstore.dev/) certificate
  details to `step certificate inspect`
- Added the `--acme` flag to the `step ca init` command to create a default ACME
  provisioner when initializing a CA.
- Added `--remote-management` flag to the `step ca init` command, which enables
  Remote Management of the CA using the Admin API.
- Added `x5c` tokens using certificates and keys in a KMS.
- Added Window's CryptoAPI support on
  [`step-kms-plugin`](https://github.com/smallstep/step-kms-plugin).
- Added `--admin-password-file` flag on admin flows.
- Added support for GitHub OAuth flows.

### Changed

- New OAuth success page with color.
- Added `x5c-roots` as alias for `x5c-root` flag.

### Removed

- Removed support for Google OOB.

## [0.22.0] - 2022-08-25

### Added

- Initial support for `step` plugins. A plugin is an executable file named with
  the format step-`name`-plugin, located in the `$PATH` or the
  `$STEPPATH/plugins` directory. These plugins will be executed using `step
  name`.
- Integration of [`step-kms-plugin`](https://github.com/smallstep/step-kms-plugin)
  on `step certificate create` and `step certificate sign`.
- Add the certificate signature to `step ssh inspect` output.
- Add the `--mtls=false` flag to force the token authorization flow on `step ca
  renew`.
- Add the `--set` and `--set-file` flag to `step certificate create` and
`step certificate sign` commands.

### Changed

- Support two latest versions of Go (1.18, 1.19)
- `step ca revoke <serial>` requires either a base 10 serial number or a value
with a prefix indicating the appropriate base.

## [0.21.0] - 2022-07-06

### Added

- Device Authorization Grant flow for input constrained devices needing OAuth
credentials. `--console-flow` flag in `step oauth` for selecting which
alternative OAuth flow to use.

### Fixed

- Added back --domain and --remove-domain flags to provisioner CRUD.

### Removed

- The `beta` prefix for remote provisioner and admin management.

## [0.20.0] - 2022-05-26

### Added

- Add commands for managing certificate issuance policies on authority, provisioner and ACME account level.
- Admin API enabled functionality for `step beta ca provisioner` and `step beta ca admin`.

### Deprecated

- step beta ca provisioner [add|remove|update] -> functionality moved to step ca provisioner [add|remove|update]
- step beta ca admin [add|remove|update] -> functionality moved to step ca admin [add|remove|update]

## [0.19.0] - 2022-04-19

### Added

- Add flags to include subscription and object ids in the Azure provisioner.
- Add support for certificate renewals after expiry using the `--allow-renewal-after-expiry` flag.
- Add `--x5c-insecure` flag.
- Add support for Azure `Managed Identity` tokens.
- Add `smtps` and `ldaps` as additional protocols supported by the `certificate inspect` command.
- Add `--sha1` flag to get `certificate fingerprint` using SHA-1 instead of the default SHA-256 algorithm.

### Changed

- Support two latest versions of Go (1.17, 1.18).

### Deprecated

- Go 1.16 support.

### Removed

### Fixed

- Fix flags to add or remove options in AWS, Azure, and GCP provisioners.
- Fix admin credentials on RAs.

### Security

## [0.18.2] - 2022-03-01

### Added

- Add Solus OS support to truststore when used in `step ca bootstrap --install`.
- Add `step completion` command to print the shell completion script.

### Changed

- IPv6 addresses are normalized as IP addresses internally.
- When the `--context` flag is provided when initializing a CA, configuration and other files will be stored in a directory named after the value provided instead of being named after the first DNS name.

### Fixed

- IP SAN support when using `step ca sign` and an ACME provisioner (see [819](https://github.com/smallstep/certificates/discussions/819)).
- Offline mode no longer requires `--ca-url` to be set.
- Add missing `TemplateData` when signing x509 certificates in offline mode.
- Improved `needs-renewal` example help texts.
- Improved `step crl inspect` reason output.

## [0.18.1] - 2022-02-03

### Added

- Add additional `emoji` and `base64-raw` encoding to the `--format` flag of `step certificate fingerprint`.
- Add `--format` flag to `step crypto key fingerprint`.
- Add `--format` flag to `step ssh fingerprint`.
- Add FreeBSD support to `step certificate install`.
- Add `step crl inspect` to inspect a certificate revocation list (CRL).
- Add `--auth-param` flag to `step oauth` for adding args to query.
- Add `--no-agent` flag to `step ssh certificate` to skip ssh-add.
- Add IP SANs support to `step ca certificate` when using an ACME provisioner.
- Add support for adding and updating Nebula provisioners.

### Changed

- Allow `step ssh login` and `step ssh logout` without positional arguments.
- Additional configuration options for SCEP provisioners.

## [0.18.0] - 2021-11-17

### Added

- Ability to use multiple certificate authority contexts without the need to change
  $STEPPATH.

### Deprecated

- Support for go 1.15

## [0.17.7] - 2021-10-20

### Added

- gocritic linter
- Allow to initialize step-ca config with Azure Key Vault using `step ca init --kms azurekms`.

### Fixed

- gocritic warnings

### Security

## [0.17.6] - 2021-10-01

### Added

- Allow override of the listen address on OIDC flows when there is an existing
  value in provisioner configuration.
- Add a way to set the redirect_uri in an OIDC flow. Allowing to get a
  certificate from containers or environments where it is hard to send traffic
  to 127.0.0.1 and where the IDP does not support the urn:ietf:wg:oauth:2.0:oob
  flow.

## [0.17.5] - 2021-09-28

## [0.17.4] - 2021-09-28

### Fixed

- Bug in step ssh certificate --offline where password-file flag was always set
to the value of provisioner-password-file flag.

## [0.17.3] - 2021-09-24

### Added

- exit code '2' for file not exists scenarios in 'needs-renewal' commands
- go 1.17 to github action test matrix
- non interactive provisioner password file flag in `step ca token --offline`

### Changed

- Using go 1.17 to build
- Have `--dns` behave as string slice flag in `step ca init`
- The way CSR is created on `step ca certificate` with OIDC to better support of admins

### Fixed

- Fix `make bootstrap` failing to get GOPATH and install `golangci-lint`.
- ipv6 address error in multi-DNS csv `step ca init`

### Security

- Use cosign to sign and upload signatures for multi-arch Docker container.
- Debian checksum

## [0.17.2] - 2021-08-30

### Security

- Sign over goreleaser github artifacts using cosign

## [0.0.2]

### Added

- `--bundle` flag to cert/inspect for inspecting all the full chain or bundle
given a path. Default behavior is unchanged; only inspect the first (leaf)
certificate.
- distribution.md with documentation on how to create releases.
- travis build and upload artifacts to GitHub Releases on tagged pushes.
- logging of invalid http requests to the oauth server

### Changed

- default PEM format encryption alg AES128 -> AES256

## [0.0.1] - 2018-08-07

### Added

- Initial version of `step`
