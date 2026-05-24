# Changelog

All notable changes to `@usehasp/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-23

### Added
- Initial implementation. Supports Hasp audit export `schema_version` `1.0`.
- Four checks: schema, hash chain, Ed25519 signature, RFC 3161 TSA anchor.
- CLI flags: `--json`, `--skip-tsa`, `--ca-file <path>`, `--verbose`, `--help`, `--version`.
- Stdin support — pass `-` as the file argument to read the export from stdin.
- `--verbose` on success prints a Detail block (schema version, tenant id, range, entries, key id, anchors).
- Published JSON Schema document at `schema/v1.0.json` for cross-language validators.
- Docs: `docs/SCHEMA.md` (field reference), `docs/AIR-GAPPED.md` (offline / long-term verification cookbook).
- README notes on Ed25519 pinning, per-check trust property, worked failure output, macOS LibreSSL caveat, and long-term verification FAQ.

### Changed
- Schema-version mismatch error now names the tool compatibility table so reviewers can find the right version to install.
- `VERSION` is now derived from `package.json` (single source of truth, no drift risk on release).
