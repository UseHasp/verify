# Changelog

All notable changes to `@usehasp/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation. Supports Hasp audit export `schema_version` `1.0`.
- Four checks: schema, hash chain, Ed25519 signature, RFC 3161 TSA anchor.
- CLI flags: `--json`, `--skip-tsa`, `--verbose`, `--help`, `--version`.
