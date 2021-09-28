# Changelog

NOTE: Please look to the technical section of the [smallstep blog](https://smallstep.com/tags/technical/)
for all release notes for step cli and certificates.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased - 0.17.5] - DATE
### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.17.4] - 2021-09-2028
### Added
### Changed
### Deprecated
### Removed
### Fixed
- Bug in step ssh certificate --offline where password-file flag was always set 
to the value of provisioner-password-file flag.
### Security

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
### Deprecated
### Removed
### Fixed
### Security

## [0.0.1] - 2018-08-07
### Added
- Initial version of `step`
