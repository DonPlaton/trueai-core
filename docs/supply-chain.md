Supply chain: what is checked, and what each check is for
=========================================================

Four gates, run together by `scripts/check_supply_chain.py` and separately in
CI. They fail together in practice — a dependency added without thought fails
three at once — so seeing one at a time turns one fix into three round trips.

```
python scripts/check_supply_chain.py
```

## Advisory tracking fails when nobody has looked

`pip-audit` answers "does a packaged dependency have a known CVE right now". Two
questions it does not answer decide whether a scanner is safe to run on hostile
files.

**What about the parsers that are not packaged dependencies?** Most artifact
bytes reach `zipfile`, `xml.etree`, `zlib`, `html.parser`, and `json`. A CPython
advisory for any of them applies directly to how TrueAI reads a hostile file, and
would pass a clean dependency audit without comment. `security/advisories.toml`
lists them as `stdlib-parser` components so they are reviewed on the same clock
as everything else.

**Has anybody looked recently?** "No known vulnerabilities" from a review done
eight months ago is a lie by omission, and a green check makes it a confident
one. So `scripts/check_advisories.py` fails on **staleness** — which means it
fails when the work stops, rather than only when a specific CVE is published.

Four ways to fail, each a different kind of neglect:

| Failure | What it means |
|---|---|
| `stale` | The ledger, or one entry in it, is older than `max_age_days`. |
| `unreviewed` | A dependency is installed that nobody classified. |
| `orphaned` | An entry describes a dependency that is no longer there, so the ledger describes a build that does not exist. |
| `expired` | An accepted risk ran out its clock. |

An acceptance needs a reason, an owner, **and an expiry**. Without an expiry it
is not an acceptance, it is a decision nobody will revisit — the gate fails when
one lapses rather than letting it become permanent by inattention.

Fetching new advisories needs the network and is deliberately not automated here.
`pip-audit` does that in hosted CI. What is automated is noticing that nobody
fetched any.

### What writing the ledger found

Filling it in is not paperwork; the gate refused to pass until every installed
distribution was classified, and classifying them surfaced this:

> `c2pa-python` declares `wheel`, `setuptools`, `toml`, `pytest`, and `requests`
> as **install** requirements. Installing the `c2pa` extra therefore puts an HTTP
> client and a test runner into an environment for a tool that advertises being
> offline.

TrueAI imports none of them, and every request TrueAI makes still goes through
[the network gate](network-and-providers.md). But their presence widens what an
attacker who achieves execution can reach, and it is exactly the sort of thing a
dependency audit reports as "no known vulnerabilities" while saying nothing at
all. It is recorded in the ledger rather than only noticed.

## SBOM completeness, not SBOM existence

`scripts/generate_sbom.py` emits CycloneDX from the installed runtime closure
with no build tooling, so the gate runs from a working tree instead of only
inside one CI provider.

`--check` fails when a component has no version, no license, or no package URL.
Those are the three fields an SBOM is *for*, and three a generator will happily
leave blank when a distribution's metadata is thin. A document with blanks is
worse than none: it passes a consumer's "do you have an SBOM" check and answers
none of their questions.

The declared component set lives in the advisory ledger rather than in a second
snapshot file — one list, checked from both ends.

The timestamp is injectable so a reproducible build can pin it. A document that
differs between two builds of the same source is not evidence of anything.

## Licenses

`scripts/check_licenses.py` compares the runtime closure against an allowlist.
It prefers `pip-licenses` and **falls back to reading installed metadata** when
that is not installed, rather than skipping: a gate that quietly does nothing
when a tool is missing is worse than one that fails, because it reports success
either way.

The two readers disagree about which metadata field to believe — `pip-licenses`
prefers the trove classifier (`ISC License (ISCL)`) and installed metadata
prefers the `License:` field (`ISC License`). The allowlist carries both
spellings of the licenses that have two, with a comment saying why. It got
longer; it did not get weaker, and a test asserts GPL and AGPL are still refused.

## Manifest

`scripts/check_manifest.py` confirms the built distribution contains what it says
it does. See [reproducible builds](reproducible-builds.md).

## Where each runs

| Gate | Locally | CI | Release |
|---|---|---|---|
| licenses | yes | yes | yes |
| advisory ledger | yes | yes | yes |
| SBOM completeness | yes | yes | yes |
| manifest | yes | yes | yes |
| `pip-audit` | yes, when network access is explicitly available | yes | yes |
| CycloneDX generation and completeness | yes | yes | yes |
| CycloneDX artifact upload/attestation | not applicable | yes | yes |

Normal TrueAI scanning remains offline. Release auditing is a separate operator
workflow whose network use is explicit and does not send scanned artifacts.
