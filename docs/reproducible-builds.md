# Reproducible builds and the auditor environment

A forensic tool asks people to trust what it reports. That trust is worth less if
nobody can check that the package they installed was built from the source they
read. This document describes how to rebuild TrueAI Core from source and compare
the result with a published artifact.

Everything here is verified by `scripts/verify_reproducible_build.py`, which is
what CI runs. Nothing in this document is aspirational.

## The pinned inputs

| Input | Pinned by |
|---|---|
| Source | Git commit, recorded in `build-inputs.json` |
| Dependencies | `uv.lock`, hash-locked for every package |
| Interpreter and OS | `Dockerfile`, base image pinned by digest |
| Build backend | `pyproject.toml` (`hatchling`), version recorded in `build-inputs.json` |
| Build timestamp | `SOURCE_DATE_EPOCH`, passed in explicitly |
| File modes | Normalised in the container, so the host OS does not leak into the archive |

`dist/build-inputs.json` records all of them alongside the SHA-256 of every
artifact produced. It is evidence about a build, not a copy of one: it stores
digests, never contents.

## Byte-for-byte reproduction

Inside the pinned container, two independent builds of the same commit produce
identical bytes:

```bash
EPOCH="$(git log -1 --pretty=%ct)"
docker build --build-arg SOURCE_DATE_EPOCH="$EPOCH" -t trueai-core:audit --no-cache .
docker create --name trueai-audit trueai-core:audit
docker cp trueai-audit:/dist ./dist-container
docker rm trueai-audit
```

Repeat with `--no-cache` and compare:

```bash
python scripts/compare_builds.py dist-container dist-container-second
```

The whole procedure, including the two builds and the comparison, is one command:

```bash
python scripts/verify_reproducible_build.py
```

## What a host build does and does not give you

Rebuilding on your own machine, outside the container, does **not** produce the
same bytes as the container build, and that is expected rather than a defect.
Two differences are contributed by the platform, not by TrueAI:

- A ZIP records the operating system that wrote it. The `create_system` field is
  `3` (Unix) from the container and `0` (Windows) from a Windows host.
- Two zlib versions compress identical input into different deflate streams. The
  uncompressed content and its CRC are the same; the compressed bytes are not.

Neither is something a build backend can normalise away, so the honest claim is
scoped: **byte-for-byte reproduction holds within one pinned environment**. Across
environments, what holds is that the artifacts carry identical files:

```bash
python scripts/compare_builds.py dist-container dist-host --content
```

`--content` compares archive members by name, size, and SHA-256. It reports
"identical content, different archive framing" when only the framing differs, and
it fails when any shipped file actually differs. It never reports a content
difference as success.

## Verifying a published artifact

1. Read `build-inputs.json` from the release. Note the commit, the
   `SOURCE_DATE_EPOCH`, and the base image digest.
2. Check out that commit.
3. Build the container with that `SOURCE_DATE_EPOCH`.
4. Compare the SHA-256 of your artifacts with the ones the record lists.

If the digests match, the published wheel was built from that source. If they do
not, run the comparison with `--content`: a framing-only difference means the
release was built in a different environment than yours, and a content difference
means the published artifact does not correspond to that source.

Release signatures and provenance attestations are produced by hosted CI, which
is a separate gate; see [release.md](release.md).

## Building from the source distribution offline

The source distribution carries `uv.lock`, the `Dockerfile`, the test suite, the
published schema, and the release scripts, so it can rebuild and re-verify itself
without network access to anything but a package index:

```bash
tar xf trueai_core-0.1.0.tar.gz
cd trueai_core-0.1.0
uv sync --frozen --all-extras
uv run pytest
uv run python scripts/check_manifest.py
```

`--frozen` fails rather than re-resolving, so a lock that does not match
`pyproject.toml` is an error instead of a silent upgrade.
