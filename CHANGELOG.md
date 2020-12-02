# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased (2.0.0 - 2020-12-xx)]
### Added
- New `phpstan` rules
- Added `infection/infection` package to test mutations
- Added Sodium library support to replace `defuse/php-encryption`
- PHP 8 support
- Can store tokens to cookies
- Access token and refresh token can be retrieved from cookie (usage of `TokenRetrieverInterface`)

### Changed
- Remove `Crypt` trait and use `CryptInterface`
- Updated tests
- GitHub Actions replaced Travis CI
- Updated `lcobucci/jwt` package to version 4
- Updated examples

### Removed
- Drop PHP 7.4 support
- Remove Prophecy `phpspec/prophecy` usage for testing
- Remove `defuse/php-encryption` support (only Sodium library used)
- Remove PSR-7 implementation (`slim/psr7`) for testing (test only with Mock)

## [1.0.0] - 2020-10-12
### Added
- First version

[Unreleased]: https://github.com/t0mmy742/token-api/compare/1.0.0...HEAD
[1.0.0]: https://github.com/t0mmy742/token-api/releases/tag/1.0.0