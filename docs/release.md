# Release engineering

## Versions

Two version numbers are published and they move independently.

| Version | Source | Meaning |
|---|---|---|
| Package version | `pyproject.toml` and `trueai/_version.py` | The distribution on PyPI. |
| Schema version | `trueai/_version.py` | The public report contract. See [schema compatibility](schema-compatibility.md). |

The package follows semantic versioning. Before `1.0.0` the minor number carries
breaking changes, so `0.2.0` may change the Python API while `0.1.1` may not.

A package release never implies a schema release. Most releases keep
`schema_version` at `0.1`.

## Tags

Tags are the release trigger and the audit record.

- Format: `v<package version>`, for example `v0.1.0` or `v0.1.0rc1`.
- Tags are annotated and created on a commit that is already green on `main`.
- `scripts/check_release_tag.py` fails the release workflow when the tag and the
  packaged version disagree, so a mistyped tag cannot publish.
- Tags are never moved or deleted after a successful publish. A mistake is fixed
  by releasing the next patch version.

```bash
git tag -a v0.1.0 -m "TrueAI Core 0.1.0"
git push origin v0.1.0
```

## What CI proves before a release

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Gate |
|---|---|
| `static-analysis` | Ruff lint, Ruff format, strict mypy. |
| `test` | Full suite on Python 3.12, 3.13, and 3.14 across Linux, macOS, and Windows. |
| `adversarial` | Hostile-input and security-boundary suites on Linux and macOS with `TRUEAI_REQUIRE_PRIVILEGED_TESTS=1`, so symlink and permission cases cannot silently skip. |
| `schema-compatibility` | The published schema contract still holds and the snapshot is current. |
| `package` | Build, `twine check --strict`, byte-for-byte reproducible rebuild, packaged-manifest check, clean-environment install, `pip check`, and an installed console-script smoke test. |
| `supply-chain` | `pip-audit` for known vulnerabilities, dependency license allowlist, CycloneDX SBOM. |

## What the release workflow adds

`.github/workflows/release.yml` runs on a `v*` tag:

1. Confirms the tag matches the packaged version.
2. Builds with `SOURCE_DATE_EPOCH` pinned to the commit date, so the artifacts are
   reproducible from the tagged source.
3. Re-runs the metadata, manifest, vulnerability, and license gates.
4. Generates a CycloneDX SBOM alongside the distributions.
5. Records SHA-256 digests for every published file.
6. Attests build provenance, binding each artifact to the workflow, commit, and
   runner.
7. Signs the distributions with Sigstore, so consumers verify without a
   long-lived signing key.
8. Publishes through PyPI trusted publishing. No API token is stored in the
   repository.

### Verifying a published artifact

```bash
python -m pip install sigstore
sigstore verify identity \
  --cert-identity "https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  trueai_core-0.1.0-py3-none-any.whl
```

## Reproducible builds

Builds are reproducible when `SOURCE_DATE_EPOCH` is pinned:

```bash
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)" python -m build --outdir dist
```

CI builds twice into separate directories and compares every artifact with
`scripts/compare_builds.py`. A non-reproducible build fails the `package` job
rather than being discovered by a downstream auditor.

## Packaged source manifest

`scripts/check_manifest.py` asserts both distributions:

- the wheel contains the package, `py.typed`, and every policy profile, and
  contains no tests, docs, scripts, skills, or workflows;
- the source distribution contains the test suite, docs, published schema, and
  release scripts, so it can rebuild and re-verify itself offline, and contains no
  virtualenv, VCS, or cache directories.

## Release checklist

1. `CHANGELOG.md` has an entry for the version with its date.
2. `pyproject.toml` and `trueai/_version.py` agree on the version.
3. `PROJECT_STATUS.md` reflects reality, not intent.
4. CI is green on the release commit, including the Windows and macOS jobs.
5. `schema/published/` contains a frozen file for the emitted `schema_version`.
6. Documentation describes only demonstrated capabilities.
7. Tag and push; confirm the release workflow published, signed, and attested.

## Support windows

- The current minor version receives fixes.
- A published schema version is readable for at least one subsequent minor
  version after its successor ships, and its `schema/published/` file is never
  removed.
- Security fixes are documented in [`../SECURITY.md`](../SECURITY.md).
