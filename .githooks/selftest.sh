#!/usr/bin/env bash
# Does the pre-commit secret scan still block?
#
# A hook nobody has seen fail is a hook nobody knows works. This builds a
# throwaway repository, stages things that must never be committed, and fails
# if any of them get through.
set -uo pipefail
HOOK="$(cd "$(dirname "$0")" && pwd)/pre-commit"
[[ -x "$HOOK" ]] || { echo "pre-commit is not executable"; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q .
git config user.email t@example.invalid
git config user.name t
mkdir -p .githooks
cp "$HOOK" .githooks/pre-commit
git config core.hooksPath .githooks

fails=0
must_pass() {
  if git commit -qm "$1" >/dev/null 2>&1; then echo "ok   $1"; else
    echo "FAIL $1 was blocked and should not have been"; fails=$((fails+1)); fi
}
must_block() {
  if git commit -qm "$1" >/dev/null 2>&1; then
    echo "FAIL $1 was committed and should have been blocked"; fails=$((fails+1))
  else echo "ok   $1 blocked"; fi
  git reset -q
}

# The bait is ASSEMBLED, never written out.
#
# Spelled literally, this file trips the very hook it is testing — which it
# did, first time. It is also the wrong file for somebody to copy a
# realistic-looking token out of. Each pattern is built from pieces that are
# harmless on their own.
h32="0123456789abcdef0123456789abcdef"
h36="0123456789abcdefghijklmnopqrstuvwxyz"

echo "hello" > README.md; git add README.md
must_pass "ordinary content"

{ printf -- '-----BE'; printf 'GIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n'; } > id_ed25519
git add -f id_ed25519; must_block "a private key"; rm -f id_ed25519

printf 'token = "%s%s01"\n' "ci" "o$h32" > cfg.toml
git add cfg.toml; must_block "a crates.io token"; rm -f cfg.toml

printf 'GITHUB_TOKEN=%s%s\n' "gh" "p_$h36" > .env
git add -f .env; must_block "a GitHub token"; rm -f .env

printf 'aws = "%s%s"\n' "AKI" "AIOSFODNN7EXAMPLE" > aws.txt
git add aws.txt; must_block "an AWS key id"; rm -f aws.txt

head -c 64 /dev/urandom > vault.cbor
git add -f vault.cbor; must_block "a vault file"; rm -f vault.cbor

echo
[[ $fails -eq 0 ]] && echo "ALL PASS" || echo "$fails FAILURES"
exit $fails
