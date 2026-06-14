# Changelog

All notable changes to Secure Credentials Kit are documented in this file.

## 0.3.1 - 2026-06-15

### Changed

- Upgraded the locked dependency set, including Cryptography 49.0.0, Django 5.2.15 and 6.0.6, and FastAPI 0.137.0.
- Restricted setuptools package discovery to prevent stale build output from being included in release wheels.

## 0.3.0 - 2026-05-31

### Added

- Added `CredentialsContainer.get_as_type()` and `CredentialsContainer.dig_as_type()` for typed credential access.

## 0.2.1 - 2026-05-20

### Changed

- Updated project homepage and issue tracker URLs to the renamed `secure-credentials-kit` repository.

## 0.2.0 - 2026-05-20

### Added

- Added master and read-only credentials key roles for separating edit access from runtime read access.
- Added Ed25519 signing and verification for encrypted credentials payloads.
- Added automatic runtime key selection that prefers read-only keys and falls back to master keys.
- Added opaque base64url key-file contents for newly generated keys, with automatic role inference from key material.
- Added backward-compatible parsing for legacy JSON key files.

### Changed

- Updated CLI and Django management command wording to describe generating credentials keys instead of a single encryption key.
- Documented the signed credentials envelope and base64url key-file format.

## 0.1.0 - 2026-05-20

### Added

- Initial package release for encrypted credentials management.
- Added framework-neutral CLI commands for generating and editing credentials.
- Added Django management commands.
- Added FastAPI helpers for loading credentials into application state.
- Added environment-specific encrypted YAML credentials files.
