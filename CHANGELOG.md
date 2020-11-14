# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- New `phpstan` rules
- Added `infection/infection` package to test mutations
- Added Sodium library support to replace `defuse/php-encryption`

### Changed
- Remove `Crypt` trait and use `CryptInterface`
- Updated tests

### Delete
- Remove Prophecy `phpspec/prophecy` usage for testing

## [1.0.0] - 2020-10-12
### Added
- First version

[Unreleased]: https://github.com/t0mmy742/token-api/compare/1.0.0...HEAD
[1.0.0]: https://github.com/t0mmy742/token-api/releases/tag/1.0.0