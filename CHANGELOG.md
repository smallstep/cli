# Changelog

NOTE: Please look to the technical section of the [smallstep blog](https://smallstep.com/tags/technical/)
for all release notes for step cli and certificates.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased - 0.17.3] - DATE
### Added
- go 1.17 to github action test matrix
### Changed
- Using go 1.17 to build
### Deprecated
### Removed
### Fixed
- Fix `make bootstrap` failing to get GOPATH and install `golangci-lint`.
### Security
- Use cosign to sign and upload signatures for multi-arch Docker container.
- Debian checksum

## [0.17.2] - 08.30.2021
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

## [0.0.1] - 08.07.2018
### Added
- Initial version of `step`
