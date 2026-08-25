# Provenance: markers, verification, and what each one proves

TrueAI keeps two things apart that are routinely conflated.

**Marker discovery** happens during a scan. It reports that literal C2PA or
Content Credentials bytes appear in a file. Anyone can write those bytes. A marker
is evidence about the file's contents and nothing more.

**Verification** is an explicit operation. It validates a signed manifest, reports whose
certificate signed it, and says whether that certificate chains to a trust anchor the operator
configured. It can run as the dedicated verify command or be explicitly attached to a scan report.

The default scan never verifies, and verification never happens implicitly. This is why a marker
finding says `"verification": "not_attempted"` unless the separate
`provenance_verifications` report field records an explicit verifier result.

## Verifying an artifact

Verification uses the C2PA reference implementation and is an optional install:

```bash
pip install "trueai-core[c2pa]"
trueai verify design.png --trust-anchors corporate-roots.pem
trueai scan design.png --verify-provenance --trust-anchors corporate-roots.pem --format json
```

`trueai doctor` reports whether the verifier is present and which version of the
reference implementation is in use.

```python
from trueai import verify_provenance

result = verify_provenance("design.png", trust_anchors="corporate-roots.pem")
if result.authenticated:
    print(result.signer.common_name)
```

`scan --verify-provenance` preserves marker findings and adds typed verification objects; it does
not rewrite a marker finding into authenticated evidence. For directory scans, eligible
verifier-supported artifacts are processed in report order. If the optional verifier is missing,
the report records `verifier_unavailable` and exits with code 3 instead of silently omitting the
requested coverage.

Every attached result is bound to the descriptor recorded by the scan. TrueAI compares the current
size and SHA-256 with the report immediately before and after invoking the verifier; a file changed
after the scan or while verification runs is rejected instead of combining findings from old bytes
with provenance from new bytes.

## The five outcomes

| Status | What it means | Exit code |
|---|---|---|
| `trusted` | Signature and content hashes validated, and the signer chains to a configured trust anchor. This is the only result that establishes provenance. | 0 |
| `valid` | The cryptography checks out, but the signer is not established as trusted. Materially weaker than `trusted`. | 1 |
| `no_manifest` | The artifact carries no manifest. Not evidence about how it was produced. | 1 |
| `invalid` | A check failed. Every failing check is reported with the verifier's own code and explanation. | 2 |
| `unsupported_container` / `verifier_unavailable` | The container cannot be read, or the optional dependency is not installed. No result is inferred. | 3 |

`valid` is not a softer way of saying `trusted`. Without a trust store there is
nothing for a certificate to chain to, so a correctly signed asset from an unknown
signer is exactly as unverified as its signer is unknown.

## Four questions, not one badge

A status is a single value, and a single value is what an interface turns into a
single badge. `trueai/core/provenance_view.py` splits every verification into
four answers that stand on their own, because they are four separate findings:

| Question | Answers |
|---|---|
| Is a provenance marker present? | `present` · `absent` · **`not_examined`** |
| Does its signature verify? | `valid` · `invalid` · **`unchecked`** · `no_signature` |
| Is the signer one you trust? | `trusted` · `not_trusted` · **`no_anchors_configured`** · **`not_established`** · `not_applicable` |
| Did a provider adapter verify a watermark? | `verified` · `not_verified` · **`unavailable`** · `not_supported` · **`not_attempted`** |

The bold answers mean *this was not determined*. They are collected in
`UNKNOWN_ANSWERS`, and an interface must not style them the way it styles a
negative result — `NO_MANIFEST` and `VERIFIER_UNAVAILABLE` were both "not green"
in a single-status view, which made "this artifact carries no provenance"
indistinguishable from "we were unable to look". One is a result and the other
is a hole in the scan.

Three of the distinctions matter enough to name:

- **`not_examined` is not `absent`.** Nothing follows from an unexamined
  artifact, including "no provenance".
- **`no_anchors_configured` is not `not_trusted`.** The first is a property of
  the scan; rendering it as the second blames an artifact for a missing
  configuration.
- **`not_established` is not `not_trusted`.** When a signature fails, the signer
  identity it carries proves nothing — asking whether that identity is trusted
  invites reading the answer as though the signature had held.

`establishes_provenance` is true only when all three C2PA facets line up. The
provider facet cannot contribute: a watermark says which tool produced
something, it carries no signed chain, and letting it raise that flag would be
exactly the conflation this exists to prevent.

`caveats()` states the ways a positive-looking facet is weaker than it looks,
and `headline()` returns the one sentence that is safe to put at the top — it
claims a verified trusted chain if and only if `establishes_provenance` does.

The facets are a projection, not report content. Everything is derived from
`ScanReport`, and adding derived state to a frozen schema would create a second
source of truth that can disagree with the first.

## Trust anchors are an operator decision

`--trust-anchors` accepts a PEM bundle path or the PEM text itself. TrueAI ships no
default trust store, because deciding whose signatures count is a policy decision
that belongs to the organization running the scan, not to the scanner.

## The network boundary

Verification is local by default. A manifest stored on a remote server is reported
by URL and never fetched. Passing `--allow-remote-manifests` is the explicit opt-in,
and the result records `remote_manifests_allowed` so a report shows which boundary
was in force.

## What verification does not do

- It does not detect statistical or robust watermarks. Provider adapters continue
  to report `VERIFICATION_UNAVAILABLE` where no public verifier exists.
- It does not prove a human or a model authored anything. It proves that a
  specific certificate signed a specific manifest over specific content.
- It does not remove, forge, or weaken provenance. Built-in policies preserve
  provenance findings, and format cleaners refuse to touch them independently of
  the policy engine.

## Test fixtures

Signed fixtures are generated at test time from a throwaway root CA and a leaf
certificate that meets the C2PA certificate profile (`tests/fixtures_provenance.py`).
Nothing in the suite chains to a real certificate authority, so the fixtures are
freely redistributable and the trust anchor returned alongside an asset is the only
thing that will ever validate it.
