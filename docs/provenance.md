# Provenance: markers, verification, and what each one proves

TrueAI keeps two things apart that are routinely conflated.

**Marker discovery** happens during a scan. It reports that literal C2PA or
Content Credentials bytes appear in a file. Anyone can write those bytes. A marker
is evidence about the file's contents and nothing more.

**Verification** is a separate, explicit operation. It validates a signed manifest,
reports whose certificate signed it, and says whether that certificate chains to a
trust anchor the operator configured.

A scan never verifies, and verification never happens implicitly. This is why the
marker finding says `"verification": "not_attempted"` rather than claiming a
result it did not obtain.

## Verifying an artifact

Verification uses the C2PA reference implementation and is an optional install:

```bash
pip install "trueai-core[c2pa]"
trueai verify design.png --trust-anchors corporate-roots.pem
```

`trueai doctor` reports whether the verifier is present and which version of the
reference implementation is in use.

```python
from trueai import verify_provenance

result = verify_provenance("design.png", trust_anchors="corporate-roots.pem")
if result.authenticated:
    print(result.signer.common_name)
```

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
