# Changelog

NOTE: Please look to the technical section of the [smallstep blog](https://smallstep.com/tags/technical/)
for all release notes for step cli and certificates.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Add additional `emoji` and `base64-raw` encoding to the `--format` flag of `step certificate fingerprint`.
- Add `--format` flag to `step crypto key fingerprint`.
- Add `--format` flag to `step ssh fingerprint`.
- Add FreeBSD support to `step certificate install`.
- Add `step crl inspect` to inspect a certificate revocation list (CRL).
- Add `--auth-param` flag to `step oauth` for adding args to query
- Add `--no-agent` flag to `step ssh certificate` to skip ssh-add
### Changed
- Allow `step ssh login` and `step ssh logout` without positional arguments.
### Deprecated
### Removed
### Fixed
### Security

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
- `--bundle` flag to cert/inspect for inpecting all the full chain or bundle
given a path. Default behavior is unchanged; only inspect the first (leaf)
certificate.
- distribution.md with documentation on how to create releases.
- travis build and upload artifacts to Github Releases on tagged pushes.
- logging of invalid http requests to the oauth server
### Changed
- default PEM format encryption alg AES128 -> AES256

## [0.0.1] - 2018-08-07
### Added
- Initial version of `step`
