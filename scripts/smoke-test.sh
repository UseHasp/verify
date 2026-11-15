#!/usr/bin/env bash
# Smoke-test the artifact that will ship: pack the package, install the tarball
# into a throwaway directory, and run the installed bin against the test fixture.
# Catches regressions that source-only tests miss: a missing `files` entry, a
# broken `bin`, a bad shebang, or a check that reaches the network when it should
# not.
#
# The fixture's tenant is a throwaway with no live published-keys endpoint, so
# its published keys are passed from disk (--keys-file); without it the
# published-key check tries to fetch them and fails.
#
# Run from the package root. Used by the release workflow (before publishing)
# and by CI on every pull request, so a failure shows up before a release.
set -euo pipefail

root="$(pwd)"
tarball="$(npm pack 2>/dev/null | tail -1)"
smoke="$(mktemp -d)"

cleanup() {
  rm -f -- "${root:?}/${tarball:?}"
  rm -rf -- "${smoke:?}"
}
trap cleanup EXIT

cd "$smoke"
npm init -y >/dev/null
npm install "${root}/${tarball}" >/dev/null

./node_modules/.bin/hasp-verify --version
./node_modules/.bin/hasp-verify "${root}/test/fixtures/valid.json" \
  --keys-file "${root}/test/fixtures/published-keys.json" \
  --skip-tsa
