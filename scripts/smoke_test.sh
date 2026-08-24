#!/usr/bin/env bash
# Exercise an installed TrueAI console script end to end.
#
# The wheel is only considered releasable when the installed entry point can
# scan, emit a valid report, clean an artifact, and return its documented exit
# codes. Importing the package in-process would not catch a broken console
# script, missing package data, or an entry point that fails on a clean machine.
set -euo pipefail

TRUEAI="${1:-trueai}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

expect_exit() {
  local expected="$1"
  local label="$2"
  shift 2
  set +e
  "$@" > /dev/null 2>&1
  local actual=$?
  set -e
  if [ "$actual" -ne "$expected" ]; then
    echo "error: $label expected exit code $expected, got $actual" >&2
    exit 1
  fi
}

"$TRUEAI" --version
"$TRUEAI" detectors list > /dev/null
"$TRUEAI" policies list > /dev/null
"$TRUEAI" plugins list > /dev/null
"$TRUEAI" doctor > /dev/null
"$TRUEAI" schema --output "$WORKDIR/schema.json" > /dev/null
python -c "import json,sys; json.load(open(sys.argv[1]))" "$WORKDIR/schema.json"
"$TRUEAI" certificates schema --output "$WORKDIR/certificate-schema.json" > /dev/null
python -c "import json,sys; json.load(open(sys.argv[1]))" "$WORKDIR/certificate-schema.json"
"$TRUEAI" certificates revocation-schema --output "$WORKDIR/revocation-schema.json" > /dev/null
python -c "import json,sys; json.load(open(sys.argv[1]))" "$WORKDIR/revocation-schema.json"
"$TRUEAI" policies bundle-schema --output "$WORKDIR/policy-bundle-schema.json" > /dev/null
python -c "import json,sys; json.load(open(sys.argv[1]))" "$WORKDIR/policy-bundle-schema.json"

# An artifact with no residue is clean under the reporting policy.
printf 'An ordinary sentence with no residue.\n' > "$WORKDIR/clean.txt"
expect_exit 0 "clean scan" "$TRUEAI" scan "$WORKDIR/clean.txt"
expect_exit 0 "clear certificate" "$TRUEAI" certificates issue "$WORKDIR/clean.txt" \
  --output "$WORKDIR/clean.audit.json"
expect_exit 0 "certificate binding" "$TRUEAI" certificates verify \
  "$WORKDIR/clean.audit.json" --artifact "$WORKDIR/clean.txt"

# Optional Ed25519 issuer authentication must work in the packaged attestation extra.
"$TRUEAI" certificates keygen --private-key "$WORKDIR/issuer.pem" \
  --public-key "$WORKDIR/issuer.pub.pem" > /dev/null
"$TRUEAI" policies bundle-create strict --output "$WORKDIR/strict-policy.json" \
  --signing-key "$WORKDIR/issuer.pem" --issuer "Smoke Test" > /dev/null
expect_exit 0 "signed policy bundle verification" "$TRUEAI" policies bundle-verify \
  "$WORKDIR/strict-policy.json" --public-key "$WORKDIR/issuer.pub.pem"
expect_exit 0 "signed certificate" "$TRUEAI" certificates issue "$WORKDIR/clean.txt" \
  --output "$WORKDIR/clean.signed.audit.json" --signing-key "$WORKDIR/issuer.pem" \
  --valid-for-days 30
expect_exit 0 "signed certificate verification" "$TRUEAI" certificates verify \
  "$WORKDIR/clean.signed.audit.json" --artifact "$WORKDIR/clean.txt" \
  --public-key "$WORKDIR/issuer.pub.pem"
expect_exit 0 "certificate revocation" "$TRUEAI" certificates revoke \
  "$WORKDIR/clean.signed.audit.json" --revocation-list "$WORKDIR/issuer.revocations.json" \
  --signing-key "$WORKDIR/issuer.pem" --reason artifact_withdrawn
expect_exit 2 "revoked certificate" "$TRUEAI" certificates verify \
  "$WORKDIR/clean.signed.audit.json" --artifact "$WORKDIR/clean.txt" \
  --public-key "$WORKDIR/issuer.pub.pem" \
  --revocation-list "$WORKDIR/issuer.revocations.json" --require-revocation-check

# Literal attribution is only a finding until a policy decides what it means.
printf 'Generated with ChatGPT\n' > "$WORKDIR/flagged.txt"
expect_exit 0 "audit scan" "$TRUEAI" scan "$WORKDIR/flagged.txt"
expect_exit 1 "safe-clean scan" "$TRUEAI" scan "$WORKDIR/flagged.txt" --policy safe-clean
expect_exit 2 "strict scan" "$TRUEAI" scan "$WORKDIR/flagged.txt" --policy strict
expect_exit 2 "signed policy scan" "$TRUEAI" scan "$WORKDIR/flagged.txt" \
  --policy-bundle "$WORKDIR/strict-policy.json" --policy-key "$WORKDIR/issuer.pub.pem"

# The JSON report must be machine-readable.
set +e
"$TRUEAI" scan "$WORKDIR/flagged.txt" --policy safe-clean \
  --format json --output "$WORKDIR/report.json" > /dev/null
set -e
python -c "import json,sys; json.load(open(sys.argv[1]))" "$WORKDIR/report.json"

# A corrupt artifact must exit 3 rather than crash.
printf 'PK\x03\x04 not really a package' > "$WORKDIR/broken.docx"
expect_exit 3 "corrupt scan" "$TRUEAI" scan "$WORKDIR/broken.docx"

# An image with no manifest is a fact, not a failure: exit 1, never a crash.
python -c "import sys; from PIL import Image; Image.new('RGB', (8, 8), (1, 2, 3)).save(sys.argv[1])"   "$WORKDIR/plain.png"
expect_exit 1 "verify without a manifest" "$TRUEAI" verify "$WORKDIR/plain.png"

# A container the verifier cannot read is reported, not guessed at.
expect_exit 3 "verify an unsupported container" "$TRUEAI" verify "$WORKDIR/clean.txt"

# Parallel scanning and caching must work through the installed script.
mkdir -p "$WORKDIR/tree/nested"
printf 'Generated with Claude\n' > "$WORKDIR/tree/nested/note.md"
expect_exit 1 "cached parallel scan" \
  "$TRUEAI" scan "$WORKDIR/tree" --policy safe-clean --jobs 4 --cache
expect_exit 1 "second cached scan" \
  "$TRUEAI" scan "$WORKDIR/tree" --policy safe-clean --jobs 4 --cache
"$TRUEAI" cache clear "$WORKDIR/tree" > /dev/null

# Cleanup must produce a verified output file next to the source.
expect_exit 0 "clean command" "$TRUEAI" clean "$WORKDIR/flagged.txt" --policy safe-clean \
  --certificate "$WORKDIR/flagged.cleaned.audit.json"
if [ ! -f "$WORKDIR/flagged.cleaned.txt" ]; then
  echo "error: cleaned output was not written" >&2
  exit 1
fi
if grep -q "ChatGPT" "$WORKDIR/flagged.cleaned.txt"; then
  echo "error: attribution survived cleanup" >&2
  exit 1
fi

echo "Installed console script passed the smoke test."
