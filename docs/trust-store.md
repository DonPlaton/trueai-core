# The trust store: what an organization trusts, and when it stopped

A `TrustProfile` answers "whose key is this" for one signature. A trust store is
what an organization actually deploys: the C2PA roots, the issuer keys, and the
plugin publisher keys a fleet of machines should honour, distributed as one
signed document with a sequence number and a lifetime.

`trueai/core/trust_store.py` fetches nothing. A store arrives as bytes — from a
file, a share, or a USB stick. If it arrives over a network it does so through
[the network gate](network-and-providers.md) like everything else.

## Three problems, not one

### Distribution: a store you cannot roll back

A store is signed, sequenced, and expires. Installing it takes the sequence this
machine already holds:

```python
result = install_trust_store(store, public_key=root_pub, known_sequence=7)
```

A store arriving at sequence 3 when 7 is installed is a rollback, and a rollback
reinstates every key the intervening sequences revoked. A verifier with no
memory cannot detect that, so the API asks for the memory rather than pretending
it is unnecessary — pass `known_sequence=None` and you get no rollback check and
know that you do not.

An expired store stops being authoritative rather than quietly continuing:
`active_anchors()` on an expired store returns nothing at all. Otherwise the
lifetime would be decorative.

Refusals come back as a list, not the first one found. An operator fixing a
stale clock should see the rollback in the same run rather than discovering it on
the next attempt.

The signature check reports three distinct failures rather than collapsing them:

| Problem | What it actually means |
|---|---|
| the public key could not be read | Wrong path, or not a PEM. Nothing is known about the store yet. |
| the wrong key for this store | The store is signed by someone; it is not this key. Not evidence of tampering. |
| the signature does not verify | The bytes and the signature disagree. This one is the alarming one. |

Telling an operator "the signature does not verify" when they typed the wrong
filename sends them looking for an attacker.

### Rotation: the gap, not the replacement

A replacement anchor names the one it replaces:

```python
TrustAnchor(anchor_id="issuer-2026", replaces="issuer-2025", not_before=…, …)
```

The interesting failure is not the replacement. It is the **gap**: if the
successor's `not_before` falls after the predecessor's `not_after`, there is a
window in which nothing verifies. Every signature made in it fails — months
later, to someone who will not connect it to a key rotation.

`rotation_problems()` reports exactly that window. `install_trust_store` surfaces
it as a **warning, not a refusal**: the gap may be deliberate, and it is the
operator's call. What is not acceptable is making it silently.

A rotation naming an anchor the store does not contain is refused outright,
because a gap that cannot be checked would otherwise be accepted with the check
quietly skipped.

### Offline updates: strictly one sequence at a time

A machine that never touches the network still needs new roots. A
`TrustStoreUpdate` carries one step and applies from a file:

```python
installed, result = apply_update(installed, update, public_key=root_pub)
```

Updates advance **exactly one sequence**. Jumping from 4 to 6 would skip whatever
5 revoked, and a revocation you skipped is a key you are still trusting. The
constraint is enforced twice — the update model refuses to describe a jump, and
`apply_update` refuses to apply one whose `from_sequence` is not what is
installed.

An update carries the whole successor rather than a diff. A diff would be
smaller and would make "what will I be trusting afterwards" a question requiring
computation. The store is small enough that clarity wins.

An update whose store belongs to a different organization is refused: a trust
store quietly changing hands is not an update. A refused update leaves the
installed store in place — never a partially applied one.

## What an anchor is trusted for

`AnchorKind` keeps four things apart: `c2pa_root`, `issuer_key`,
`plugin_publisher`, `timestamp_authority`. Trusting a key to sign C2PA manifests
is not trusting it to publish plugins, and a store that conflated them would
silently widen every anchor it holds.

The material's shape is validated at authoring time, not where it is consumed —
an `issuer_key` holds a `sha256:…` key id, a `c2pa_root` holds a PEM. The
consumer is `to_trust_profile()` or `c2pa_anchor_pems()`, running long after the
store was authored, on a machine that cannot fix it.

## Consuming a store

```python
profile = store.to_trust_profile()     # feeds resolve_identity
roots = store.c2pa_anchor_pems()       # feeds C2PA verification
```

Both are projections, not second sources of truth. The store is what the
organization deploys; the profile is the shape one verification call wants. Both
apply the store's lifetime, each anchor's window, and every revocation before
returning anything.

## What this does not do

It does not fetch, does not phone home, and does not ship a default. Deciding
which organizations to trust is a policy decision belonging to whoever runs the
scan — the same reason TrueAI ships no default `TrustProfile`.
