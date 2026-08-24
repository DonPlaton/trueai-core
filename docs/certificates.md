# Audit certificates

TrueAI audit certificates are content-bound records of a completed scan. They answer a narrow,
auditable question: did this version and configuration of TrueAI report any indicator in its
documented scope for these exact bytes?

They do not prove human authorship, originality, or that AI assistance never occurred. A detector
can only report evidence it knows how to inspect, and heuristic findings remain heuristic.

## Issue and verify

```console
trueai certificates issue deliverable.pdf --output deliverable.audit.json
trueai certificates verify deliverable.audit.json --artifact deliverable.pdf
```

For an authenticated issuer identity, install `trueai-core[attestation]`, generate an Ed25519 key,
and sign during issuance:

```console
trueai certificates keygen --private-key issuer.pem --public-key issuer.pub.pem
trueai certificates issue deliverable.pdf --output deliverable.audit.json --signing-key issuer.pem --valid-for-days 90
trueai certificates verify deliverable.audit.json --artifact deliverable.pdf --public-key issuer.pub.pem
```

The private key is never embedded in a certificate. TrueAI refuses to overwrite existing key or
certificate files. Key distribution, hardware-backed custody, and organization identity remain
operator responsibilities.

## Validity and revocation

`--valid-for-days` adds a signed `expires_at` claim. Verification fails before `issued_at` or at and
after `expires_at`. A certificate without this optional field remains verifiable but explicitly
reports that no expiry was recorded; enterprise policies should require finite validity.

An issuer can withdraw a signed certificate by publishing a signed, finite-lifetime revocation
list:

```console
trueai certificates revoke deliverable.audit.json \
  --revocation-list issuer.revocations.json \
  --signing-key issuer.pem \
  --reason artifact_withdrawn

trueai certificates verify deliverable.audit.json \
  --artifact deliverable.pdf \
  --public-key issuer.pub.pem \
  --revocation-list issuer.revocations.json \
  --require-revocation-check
```

Every update verifies the previous list, increments its sequence, retains prior entries, sorts them
deterministically, and publishes the replacement atomically. Verification checks the list signature,
issuer key ID, issue time, expiry, and selected certificate ID. An unsigned, stale, wrong-issuer, or
missing list cannot satisfy `--require-revocation-check`.

This is an offline issuer list, not a public PKI or transparency service. A verifier that has never
seen a newer sequence cannot detect rollback to an older still-valid signed list. Organization
identity, trusted timestamps, hardware-backed keys, online distribution, and rollback-resistant
transparency remain enterprise integration work. A `key_compromise` reason also needs an
out-of-band trusted distribution path because a compromised issuer key cannot vouch for itself.

## Bound claims

The `TAI1-…` identifier hashes the canonical certificate claims. Those claims include:

- exact file SHA-256 or ordered directory/repository inventory digest;
- exact scan report SHA-256 and scan ID;
- optional finite expiry;
- TrueAI package and report-schema versions;
- policy, detectors that ran, and portable resource limits;
- scan diagnostics and whether coverage was complete;
- individual scoped indicator and protected-provenance finding IDs;
- whether experimental style detectors were enabled;
- explicit limitations attached to every certificate.

Changing a claim invalidates the content ID. Changing an artifact invalidates artifact verification.
When Ed25519 is used, changing any signed claim also invalidates the issuer signature.

An unsigned certificate is tamper evident only relative to its identifier: anyone can construct a
new unsigned certificate and a matching new identifier. A valid Ed25519 signature is required when
the identity of the issuer matters.

## Status semantics

| Status | Meaning |
|---|---|
| `clear` | The scan completed and no machine-assistance, generator-tool, provider-watermark, or enabled heuristic-style indicator was detected in scope. |
| `indicators_detected` | At least one scoped finding exists. The certificate carries its finding ID. |
| `incomplete` | A diagnostic or missing artifact hash prevents a clearance statement. |

C2PA markers are listed separately as protected provenance. Their presence is not automatically an
AI-generation indicator; authenticated C2PA validation remains the separate `trueai verify`
operation.

Unicode findings are also context sensitive. A suspicious/invisible/control classification is in
certificate indicator scope; a valid leading BOM, typographic spacing, ZWJ/ZWNJ, or variation
selector remains disclosed in the scan report but is not promoted into a machine-generation claim.

## Post-clean certificates

```console
trueai clean report.docx --policy client-delivery --certificate report.cleaned.audit.json
```

The certificate is issued from a fresh scan of the output after the cleaner's integrity gate passes.
If deterministic residue remains, a heuristic still fires, or verification is incomplete, the
certificate records that state and the CLI does not return a clean success.
