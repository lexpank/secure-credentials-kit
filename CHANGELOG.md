# Changelog

All notable changes to Secure Credentials Kit are documented in this file.

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
