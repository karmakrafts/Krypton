# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- macOS and iOS building, testing and publication tasks to CI configuration
- Linux ARM64 target support
- Support for SHA-1 digest algorithm
- API for Key Derivation Functions (KDFs) with support for PBKDF2, HKDF, the Argon2 family

### Changed
- Complete restructuring of the API. Removed internal APIs in favor of modular algorithm interface.

### Fixed
- OAEPWithSHA-1AndMGF1Padding and OAEPWithSHA-256AndMGF1Padding work on OpenSSL targets


## v1.0.0.25

### Added
- Add documentation to internal APIs
- Add more documentation to the project
- Add documentation for common cipher
- Add signature

### Changed
- Refactor internal key generator API
- Refactor internal parameter generator API
- Refactor internal cipher API
- Downgrade Kotlin from 2.0.20 to 2.0.10
