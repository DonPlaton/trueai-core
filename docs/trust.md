# Trust: key custody, identity, time, and ordering

Certificates, policy bundles, and process attestations all sign things. Four
questions decide what those signatures are worth, and each is a place where a
system can quietly claim more than it knows.

## Key custody: who could have signed this

TrueAI's default is a private key file on disk. Anyone who can read that file can
sign as its owner, and the provider is named `local-key-file` so nobody mistakes
it for something stronger.

`SigningProvider` is the seam for better custody:

```python
from trueai.core.trust import ExternalSigningProvider

provider = ExternalSigningProvider(
    name="corporate-kms",
    public_key="signer.pub",          # so a verifier can check without asking the KMS
    signer=kms_sign,                  # bytes in, raw Ed25519 signature out
)
```

The private key never enters a TrueAI process. The provider decides what
authorisation signing requires — a hardware token, an approval workflow, an
audit log — and TrueAI only hands over canonical bytes.

A provider that returns a signature its own public key does not verify fails
immediately, at signing time. Discovering that at verification time means an
unusable artifact was already published.

## Identity: whose key is it

Possession of an Ed25519 key is not organizational identity. It is possession of
a key.

A key becomes an organization's key because a **trust profile** the operator
configured says so, for a stated period:

```python
from trueai.core.trust import IssuerBinding, TrustProfile, resolve_identity

profile = TrustProfile(
    profile_id="acme-2026",
    issued_at=now,
    bindings=(
        IssuerBinding(
            key_id="sha256:…",
            organization="ACME Research",
            organization_id="acme.example",
            not_before=start,
            not_after=end,
            roles=("release",),
        ),
    ),
)
identity = resolve_identity(key_id, profile=profile, root_public_key="root.pub")
```

Three assurance levels, and the difference between them is the point:

| Assurance | What it means |
|---|---|
| `key_only` | The signature verified. Nothing says whose key it is. |
| `profile_bound` | A configured profile names this key, in force at this moment. |
| `root_attested` | The profile itself is signed by a root the operator configured. |

TrueAI ships **no default profile**. Deciding which organizations to trust is a
policy decision belonging to whoever runs the scan.

Verification keeps these apart deliberately:

- `authenticated_declaration` — an identified claimant signed these bytes;
- `organizationally_attributed` — a trust profile names the organization.

Collapsing them is how "someone signed this" becomes "a company vouched for
this".

## Time: when did these bytes exist

A `signed_at` field is the signer's own claim. A signer who wants to backdate
simply writes an earlier date. A **timestamp token** is a separate authority's
statement over the digest, which is what makes the time evidence.

Two providers:

**`OfflineTimestampProvider`** — a designated timestamping key, held by a separate
role, signs the digest with the time it saw it. This is the "or equivalent" in
"RFC 3161 or equivalent". It defends against a signer backdating their own record.
It does not defend against the timestamping role itself lying, and its clock is
the machine's clock.

**`NetworkTimestampProvider`** — a real RFC 3161 authority. It requires
`NetworkPolicy.EXPLICIT_ONLY` *and* an endpoint the operator allowlisted, and the
HTTP transport is supplied by the caller. TrueAI embeds no network client: a
forensic tool that can reach the network by default is a different product with a
different threat model.

An RFC 3161 token is recorded but not parsed. `verify_timestamp` reports it as
**not established** with an explanation, because an opaque blob is not evidence
just because it is present. Verify it with a TSA-aware verifier.

Normal scanning never contacts an authority. Asking for a trusted timestamp is a
separate, deliberate act.

## Ordering: is this the current state

A revocation list that can be replaced with an older copy revokes nothing. A
policy bundle that can be rolled back enforces nothing.

`TransparencyLog` is append-only with sequence numbers and a hash chain:

- an **edited** entry breaks the chain;
- a **removed** entry breaks sequence contiguity;
- an **older copy** is caught by comparing against the sequence a verifier saw
  before;
- a **rewritten history of the same length** is caught by checking that the
  previously seen head still exists in the log.

The last two only work if the verifier remembers something, so
`verify_transparency_log` takes `known_head` and `known_sequence`. A verifier with
no memory cannot detect a rollback, and the API makes that explicit rather than
pretending otherwise.

Appending clears any maintainer signature, because a maintainer signs a state,
not a prefix of one.

## Fleet history: retention, access, privacy, export

These are the contracts a commercial fleet product must honour. They are stated
here because the open-source scanner is where the boundary is enforced: it adds
no telemetry, so anything a fleet product knows was sent to it deliberately.

**Retention.** Scan reports, certificates, and attestations are retained only for
a period the customer sets, with a documented default and a hard maximum. Expiry
deletes; it does not archive to somewhere the customer cannot see.

**Access.** Findings can reveal what is in private artifacts, so read access is
per-project and least-privilege by default. Administrative access to another
team's findings is a distinct, logged permission, not a side effect of being an
administrator.

**Privacy.** Evidence is referenced by digest. A fleet service stores what a
record contains, and a record deliberately does not contain prompts, source
documents, credentials, or personal identifiers. Any feature that would upload
those requires separate, explicit, revocable consent and must be refusable
without losing the rest of the product.

**Export.** Everything a customer put in comes back out in the published schemas —
reports, certificates, attestations, policy bundles, transparency logs — with no
proprietary re-encoding. A customer who leaves takes verifiable records, not
screenshots.

**No telemetry in core.** The open-source scanner performs no network requests
during normal operation and reports nothing about what it scanned. That is a
property of the code, checked by `trueai doctor` and stated in
[`SECURITY.md`](../SECURITY.md), not a promise in a privacy policy.

## What is not implemented

- RFC 3161 token parsing and TSA certificate-chain validation. Tokens are carried
  and reported as unverified.
- Certificate-chain-based identity (X.509 / PKI). The trust profile is a signed
  issuer registry, which is simpler and offline-verifiable but not a PKI.
- A distributed transparency service. The log is a local structure with rollback
  detection; witnessing across parties is future work.
