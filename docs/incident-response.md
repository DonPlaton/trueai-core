# Incident response: five things that go wrong, and what to do about each

A forensic tool has an unusual obligation when it fails. The reports it produced
before the failure are still in circulation, and somebody may be relying on one.
So every process below has the same second half: **decide what already-issued
evidence is still worth**, and say so publicly rather than leaving it implied.

The five are separate because they have different blast radii and different
people to tell. Collapsing them into one "security incident" procedure means the
narrow ones get the heavy process and the heavy ones get the narrow one.

| Incident | What is at risk | Who has to be told |
|---|---|---|
| [Vulnerability report](#1-a-vulnerability-report) | Everyone running the version | Reporter, then users, on a coordinated date |
| [Plugin incident](#2-a-plugin-incident) | Operators who installed that plugin | The publisher, then operators |
| [Trust store compromise](#3-trust-store-compromise) | Every provenance verdict made under it | Every fleet consuming the store |
| [Certificate misissuance](#4-certificate-misissuance-or-key-compromise) | Every certificate that key signed | Certificate holders and relying parties |
| [A bad release](#5-a-release-that-has-to-be-rolled-back) | Whoever installed it | Users, before they upgrade further |

---

## 1. A vulnerability report

[`SECURITY.md`](../SECURITY.md) covers where to send one and what to include.
What happens after:

1. **Acknowledge, and say what happens next.** A reporter who hears nothing
   assumes nothing is happening, and that is when a private report becomes a
   public one.
2. **Reproduce with a synthetic fixture.** A reproducer built from a real
   document cannot be committed, and a bug without a committed fixture comes
   back. `QA-03` requires the fixture; this is where it gets written.
3. **Decide the blast radius before the fix.** A parser escape means every report
   produced by an affected version was produced by a process that could have been
   compromised. That is a different statement from "the scan missed something",
   and users need the first one, not a changelog line.
4. **Fix, with the fixture in the same commit.** A fix without a test is a fix
   that gets reverted by the next refactor.
5. **Coordinate a date.** No bounty and no response-time guarantee are offered
   pre-release, and saying so plainly is better than an SLA nobody staffs.
6. **Publish an advisory naming the affected versions**, and add the component to
   the [advisory ledger](supply-chain.md) if it is not already there.

## 2. A plugin incident

A third-party detector that mutated artifacts, exceeded its declared
capabilities, or shipped a signed distribution containing something else.

1. **Establish what actually ran.** The report says: a detector that mutated an
   artifact produces a `detector_mutation` diagnostic at CRITICAL severity, and
   the whole-corpus sweep names the paths that appeared. A plugin the host
   refused produces `plugin_rejected`. Read those before anything else.
2. **Revoke the distribution.** `DistributionRevocation` with a reason and,
   where there is one, a replacement version. An allowlist entry pinned to the
   revoked content identifier stops it loading.
3. **Tell the publisher first, then operators.** Publishers can ship a fix;
   operators can only stop using it. Telling operators first turns a fixable bug
   into a support incident for someone who cannot fix it.
4. **Say what the affected scans are worth.** A plugin that mutated artifacts
   invalidates the *integrity* claim of every scan it ran in, not the findings of
   the other detectors. A plugin that forged findings invalidates its own
   findings and nothing else. Those are different, and an advisory that says
   "discard your reports" when only one detector was affected teaches people to
   ignore the next one.
5. **Check the capability grant.** A plugin that exceeded its manifest exceeded
   the broker too, and that is a TrueAI bug as well as a plugin incident — it
   belongs in process 1 in parallel.

See [plugins](plugins.md) for the host side.

## 3. Trust store compromise

An issuer key that signed a [trust store](trust-store.md) is compromised, or a
store was distributed with an anchor that should not have been in it.

1. **Publish a new store at the next sequence, with the anchor revoked.**
   Revocation is what reaches machines that already installed the bad one;
   removing the anchor silently would leave every already-installed store
   trusting it.
2. **Do not skip a sequence.** Updates apply one at a time precisely so a
   revocation cannot be missed. If sequence 5 revoked something, a fleet on 4
   must apply 5 before 6.
3. **Assume the window, then state it.** Every provenance verdict of `trusted`
   made under the compromised anchor, between the compromise and the revocation,
   was made against a key that should not have counted. The four
   [provenance facets](provenance.md) matter here: the *signature* was still
   valid, and only *signer trust* was wrong. An advisory that says "provenance
   verification was broken" overstates it and is the kind of overstatement that
   gets a correction printed later.
4. **Re-verify what matters.** Re-running verification against the new store is
   cheap; the point is that it can be done at all, which is why the store carries
   a sequence and a digest.

## 4. Certificate misissuance or key compromise

A [certificate](certificates.md) was issued over the wrong artifact, or the key
that signed certificates is compromised.

1. **Revoke, with a reason.** `trueai certificates revoke` produces a revocation
   entry; the reason is part of the record because "revoked" alone tells a
   relying party nothing about whether to re-check or to discard.
2. **Publish the revocation list, signed.** A revocation nobody can fetch is a
   revocation that did not happen.
3. **Say what a TrueAI certificate ever claimed.** It attests that a named
   scanner version and detector scope found no scoped indicators in exact
   artifact bytes at a recorded time. It never certified human authorship and
   never certified that AI was not used. A misissuance advisory that lets people
   believe otherwise makes the original overclaim on the project's behalf.
4. **For key compromise, revoke every certificate that key signed** — not only
   the ones known to be wrong. A compromised key means an attacker could have
   signed anything, and a partial revocation invites relying parties to trust the
   remainder.

## 5. A release that has to be rolled back

1. **Yank rather than delete.** A deleted release breaks every lockfile that
   pinned it, including ones belonging to people the bug never affected.
2. **State which versions are affected and which are not.** "Upgrade
   immediately" without a version range means everybody upgrades, including
   people on an unaffected version who now carry a fresh regression risk for
   nothing.
3. **Re-run the release gates on the replacement** —
   [supply chain](supply-chain.md), the schema and API snapshots, the reproducible
   build, and the manifest. A hurried replacement is exactly when a second
   problem ships.
4. **If reports were wrong, say what to do with the ones already issued.** This
   is the obligation particular to a forensic tool. A scanner that under-reported
   for two releases means the clean reports produced in that window meant less
   than they said, and the people holding them have to be told what to re-run.
5. **Add the regression fixture before the replacement ships.** Otherwise the
   next release reintroduces it.

See [releases](release.md) for the mechanics.

---

## What every process shares

**Say what already-issued evidence is worth.** It is the second half of all five,
and it is the half that gets left out, because it is the part that admits
something was believed on the strength of a wrong answer.

**Do not overstate the blast radius.** "Discard all reports" when one detector
was affected, or "provenance verification was broken" when only signer trust was
wrong, teaches people to discount the next advisory. Precision is not a courtesy
here; it is what keeps the channel usable.

**Name versions, sequences, and identifiers.** Every artifact this project issues
is content-addressed and versioned — certificates, attestations, plugin
distributions, trust stores, model manifests — specifically so an advisory can
name exactly what is affected instead of a date range.
