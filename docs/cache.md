# The incremental cache: bounded, ordered, and safe to prune

`--cache` reuses detector output for content that has not changed. The key
covers the artifact digest, its logical path, its type, the enabled detector set,
the resource limits, and the package and schema versions, so a hit is only ever
an exact match and a changed byte can never return a stale result.

Everything below is about the other half: what happens when the cache grows,
which entries go first, and what a prune will refuse to touch.

## It has a ceiling

An unbounded cache beside a repository is a disk-space bug waiting for a large
enough checkout. `ScanCache` takes a `max_bytes` budget — 256 MB by default —
and the engine enforces it at the end of every scan. A budget below one entry is
refused at construction: it could never hold anything, so it is a configuration
error rather than a policy.

The end-of-scan check adds up file sizes without parsing anything. At a hundred
thousand entries, parsing each one to total them would cost more than the cache
saves.

## Eviction order is defined, not incidental

Determinism here means the property that matters: **the same inventory, the same
budget, and the same run remove the same entries**. Not an order that depends on
how a filesystem enumerates a directory, and not one that depends on a timestamp
whose resolution differs between platforms and which a copy or a restore
destroys.

| Order | Group | Why it is there |
|---|---|---|
| 1 | Written under a different package, schema, or cache format version | Those versions are part of the key, so the entry is not merely stale — it is **unreachable**. Evicting anything else first would be strictly worse. |
| 2 | Not used in this run, oldest generation first | The ones this scan did not want. |
| 3 | Used in this run, oldest generation first | Kept longest, because something just needed them. |
| — | Ties inside a group | Broken by key, so the order is never ambiguous. |

`ScanCache.eviction_order()` returns that list, and `trueai cache inspect
--entries N` prints it. Which entries would go is a question an operator should
be able to ask before, not after.

### Generations

A *generation* is one scan. An instance takes the next number from a small
counter file the first time it writes, and stamps every entry it writes with it.
That is one small read and one small write per scan rather than one per entry,
and it makes "which entries are older" a property of recorded data rather than
of file metadata.

Entries hit during a run are remembered in memory, not written back. Rewriting an
entry on every hit would cost roughly what a miss costs and undo the point of
having a cache; the in-memory set is enough to keep this run's working set until
last.

A counter that cannot be read or written does not stop the cache. Every entry
shares a generation and eviction falls back to key order.

## Inspection reports what should not be there

```
trueai cache inspect ./repository
```

Three categories, kept apart:

- **Entries** — parsed, with size, generation, and the versions they were written
  under.
- **Damaged** — a file at an entry location that will not parse. Counted apart
  from a miss, because "the cache did not help" and "the cache is unhealthy" are
  different problems and one blended hit rate hides the second.
- **Unrecognised** — a file under the cache directory that this cache did not
  write. Reported and **left in place**. A cache directory is not somewhere to be
  confident about what is safe to delete.

A path counts as an entry only when its shard directory matches its key, its name
is a 64-character hex digest, and it parses. A JSON file in the wrong shard is an
intruder, not an entry.

## Pruning takes an explicit rule

```
trueai cache prune ./repository --unreachable --yes
trueai cache prune ./repository --older-than 12 --yes
trueai cache prune ./repository --to-fit 50000000 --yes
```

No rule removes nothing, and the command says so rather than doing something
plausible. A prune that defaulted to deleting everything would make a mistyped
command destructive, and this is the one place where a wrong deletion is silent:
the next scan is merely slower, so nobody notices what went missing. `--yes` is
required on top, because pruning deletes stored results.

`--to-fit` uses the same order as automatic eviction, so a manual prune and an
automatic one cannot disagree about what matters least.

To remove everything, `trueai cache clear` is the command that says so.

### What a prune refuses

Link safety is re-checked at deletion time, not only at inspection time: a link
could have been placed in between, and a delete that follows one leaves the cache
directory entirely. Refusals are reported with their reason rather than counted
as successes.

## Where the cache lives

Beside what it describes — `.trueai/cache` under the scanned tree — so deleting a
checkout deletes its cache with it, and a scan never writes outside the tree the
operator pointed at. Discovery ignores `.trueai/`, so the cache can never become
its own input.

`trueai cache path ./repository` prints the location.
