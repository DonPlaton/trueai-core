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
| `supply-chain` | `pip-audit` for known vulnerabilities, the dependency license allowlist, the [advisory ledger](supply-chain.md) — which fails when nobody has reviewed recently rather than only when a CVE appears — and a CycloneDX SBOM checked for completeness. |

## What the release workflow adds

`.github/workflows/release.yml` runs on a `v*` tag or as an explicitly selected
manual dry run/TestPyPI run:

1. Re-runs Ruff, strict mypy, all tests, schema/API snapshots, documentation,
   licenses, advisories, SBOM completeness, and the packaged manifest.
2. Confirms a release tag matches the packaged version. A manual production
   publish is also refused unless the selected ref is a `v*` tag.
3. Installs the release toolchain from `uv.lock` and builds with PEP 517 isolation
   disabled, so Hatchling cannot drift outside the lock.
4. Builds with `SOURCE_DATE_EPOCH` pinned to the commit date.
5. Audits the hash-locked runtime closure, not the build/audit environment.
6. Generates a reproducible CycloneDX runtime SBOM and `build-inputs.json`.
7. Records SHA-256 digests for the wheel, sdist, SBOM, and build-input record.
8. Creates GitHub build-provenance and SBOM attestations for the distributions.
9. Signs and immediately verifies every release evidence file with Sigstore.
10. Publishes through a protected TestPyPI or PyPI environment with trusted
    publishing. No API token is stored in the repository.

Every third-party action is pinned to a full commit SHA. Dependabot proposes
updates to those pins; a mutable tag is never executed directly by a release.

### Verifying a published artifact

Start with the digest file, then verify GitHub's hosted attestation against the
repository that issued it:

```bash
sha256sum --check SHA256SUMS
gh attestation verify trueai_core-0.1.0-py3-none-any.whl --repo OWNER/REPOSITORY
gh attestation verify trueai_core-0.1.0.tar.gz --repo OWNER/REPOSITORY
```

The release also carries Sigstore bundles for independent identity verification:

```bash
python -m pip install sigstore
sigstore verify identity trueai_core-0.1.0-py3-none-any.whl \
  --cert-identity "https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

The adjacent `.sigstore.json` bundle is consumed automatically. See the
versioned [Sigstore Python documentation](https://docs.sigstore.dev/language_clients/python/)
when upgrading the release action or verifier.

## Reproducible builds

Builds are reproducible when `SOURCE_DATE_EPOCH` is pinned:

```bash
uv sync --frozen --all-extras --group release
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)" \
  uv run python -m build --no-isolation --outdir dist
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

## Activating the four external gates

The repository contains the gates, but it currently has no Git remote and no
hosted identity. Complete the following once a GitHub repository and package
owner exist.

### 1. Hosted CI (`REL-01`)

1. Create the GitHub repository, push the full history, and allow GitHub Actions.
2. Set the repository's default Actions permission to read-only. The release
   jobs request only their scoped OIDC/attestation permissions.
3. Run `.github/workflows/ci.yml` from `workflow_dispatch` once. Confirm all
   Python 3.12–3.14 jobs on Linux, macOS, and Windows, both POSIX adversarial
   jobs, authenticated C2PA verification, plugin confinement, packaging,
   reproducibility, and supply-chain jobs are green.
4. After the first run creates stable check names, protect `main` and require
   the relevant CI checks. Do not permit a force push to release tags.
5. Enable Dependabot and repository secret scanning. A local fallback review is
   useful, but hosted history scanning is the durable control.

### 2. TestPyPI and PyPI trusted publishing (`REL-02`)

1. Create protected GitHub environments named exactly `testpypi` and `pypi`.
   Limit `pypi` to protected `v*` tags and require manual approval where the
   organization has an independent reviewer.
2. In TestPyPI and PyPI, configure a trusted publisher for the GitHub owner,
   repository, workflow file `release.yml`, and the matching environment name.
   A new PyPI project can use a pending publisher, but the project name is not
   reserved until the first successful upload.
3. Dispatch the Release workflow with target `testpypi`. TestPyPI does not allow
   replacing an existing version, so use a fresh development/RC version for each
   publication exercise.
4. Install the TestPyPI artifact into a clean environment, run `trueai doctor`,
   `trueai --help`, and a representative local scan, then verify its hashes and
   attestations.

The environment protection and trusted-publisher security model are documented
by [GitHub](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
and [PyPI](https://docs.pypi.org/trusted-publishers/security-model/).

### 3. Signed release candidate (`REL-03`)

1. Bump the package version to the intended RC and update `CHANGELOG.md`.
2. Create an annotated matching tag, for example `v0.1.0rc1`; the production job
   cannot run from an untagged branch.
3. Let hosted CI build, attest, sign, verify, and publish. Do not upload locally
   built replacements under the same release.
4. On a clean machine, download the complete evidence set, run the digest and
   GitHub-attestation checks above, inspect `build-inputs.json` and the SBOM,
   install the wheel, and run the smoke tests.

GitHub documents clean-machine verification in
[Verifying artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

### 4. Design-partner validation (`PROC-12`)

This is not a CI checkbox. Recruit consenting pairs with a real acceptance
relationship: researcher/reviewer, software vendor/customer, creator/client,
and course team/student representative. Agree on the evaluation profile before
the deliverable, record disagreements and false interpretations, and publish
the rubric revision history. Keep the process-attestation schema outside the
frozen public API until at least two domains have completed pilots; otherwise
the product would freeze the authors' assumptions before anyone external had a
chance to challenge them.

## Support windows

- The current minor version receives fixes.
- A published schema version is readable for at least one subsequent minor
  version after its successor ships, and its `schema/published/` file is never
  removed.
- Security fixes are documented in [`../SECURITY.md`](../SECURITY.md).
