# The network boundary, and what admits a provider adapter

TrueAI runs offline. The few operations that could benefit from a remote
service — a timestamp authority, a provider's verification API — go through one
gate or do not happen.

## Six conditions, all of them

`trueai/core/network.py` refuses a request unless every one holds:

| Condition | Why it is separate |
|---|---|
| **Policy** is `NetworkPolicy.EXPLICIT_ONLY` | The default is `OFFLINE`. A caller that did not think about the network does not get it. |
| **Consent** is recorded | A policy flag says the software *may*; consent says a person *decided*. Collapsing them lets a configuration default stand in for a human. |
| **Endpoint** is allowlisted | An exact URL the operator wrote down — not a host pattern, not a scheme. |
| **Limits** are set | A timeout and a response-size cap, so a hostile or broken endpoint cannot hold a scan open or fill memory. |
| **Credentials** are per-request | Produced by a caller-supplied callable, given the endpoint being contacted. The gate holds none. |
| **Metadata** is recorded | Every attempt, allowed or refused. |

Consent is scoped to endpoints *and* a purpose. Consent to check a watermark is
not consent to upload a document, and consent for one service is not consent for
another that happens to be on the same allowlist.

TrueAI embeds no HTTP client. The transport is supplied by the caller, which
keeps that dependency out of a scanner and makes the boundary something an
auditor can see rather than something they have to trust.

## The audit trail records refusals

```python
gate.offline_audit()
# refused https://verify.example.test/: the network policy is offline; …
```

This is the part that is easy to leave out and the part that matters most. A
forensic tool needs to be able to prove it did *not* contact anything, and a log
that only records successes cannot do that.

What a record carries: endpoint, purpose, who granted consent, whether it was
allowed, how long it took, how many bytes came back, and the **names** of the
headers sent. What it never carries: the request body, the response body, or a
header value — because a header value can be a credential.

## Everything goes through it

`NetworkTimestampProvider` used to carry its own copy of the policy and
allowlist checks. It now builds or accepts a `NetworkGate` and calls through it,
so "did this tool contact anything" has one answer, one set of rules, and one
audit trail. Its original two-argument transport shape still works — it is
adapted to the gate's protocol rather than replaced, because changing it would
break every caller who wrote one.

A provider adapter is offline unless handed a configured gate, and an adapter
that has not declared `network_required` cannot make a request at all, even with
one.

## What admits a provider adapter

An adapter is written when a provider publishes something a third party can
actually run. It is not written because a provider is known to watermark,
because a paper describes an approach, or because a heuristic seems to work.
Those produce a plausible answer with nothing behind it, and a plausible answer
about provenance is worse than an honest "unavailable".

`AdmissionCriteria` requires **all four**:

1. a published verifier, API, or specification;
2. independently runnable, without a private agreement or a secret key;
3. semantics specified well enough that a wrong answer is distinguishable from a
   bug in this code;
4. a stable, versioned contract.

Three out of four describes a watermark someone reverse-engineered. Shipping that
would mean presenting a guess as a verification.

### Where each provider stands

| Provider | Admitted | Why |
|---|---|---|
| C2PA | **yes** | Published specification and open implementation. TrueAI verifies through that implementation rather than reimplementing it. |
| Google | no | SynthID detection is offered through Google's own surfaces, not as a specification or a verifier a third party can run. |
| OpenAI | no | No public verifier, API, or specification. |
| Anthropic | no | No public verifier, API, or specification. |
| Generic | no | A placeholder so an unrecognised marker has somewhere honest to land. |

`PROVIDER_ASSESSMENTS` keeps this in code rather than only in prose, so the
reasoning ships with the software and changing it means changing a test. An
unadmitted provider reports `VERIFICATION_UNAVAILABLE` **with the specific
criteria it fails**, so "unavailable" is a position with reasons rather than a
shrug.

## What this does not do

No adapter here infers a watermark algorithm, a secret key, or a removal method.
That is a standing constraint, not a gap waiting to be filled: see
[safety](safety.md).
