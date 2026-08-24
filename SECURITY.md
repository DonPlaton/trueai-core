# Security policy

## Reporting a vulnerability

Do not open a public issue for an unpatched vulnerability involving parser escape, path traversal,
resource exhaustion, arbitrary execution, or provenance forgery. Send a private report to the
maintainer address published in the repository security settings. Include the affected version,
minimal synthetic reproducer, impact, and suggested mitigation if known.

No bounty or response-time guarantee exists during the pre-release phase. Maintainers will
acknowledge valid reports and coordinate disclosure when contact information is available.

## Security model

TrueAI treats every artifact as hostile:

- scanners never execute HTML, SVG scripts, macros, attachments, hooks, or embedded objects;
- file and archive reads are bounded;
- finding counts, parser events, Git subprocess output, and recursive file discovery are bounded;
- OPC entry names, compression ratios, entry counts, and total expanded size are validated;
- XML DTDs, external entities, and entity expansion are forbidden;
- symlinks are not followed by default and may not escape the scan root;
- raster dimensions are bounded before metadata processing;
- RIFF, ID3, FLAC, ISO BMFF/QuickTime, and EBML metadata readers bound events and text values and
  never invoke media codecs;
- WAV, MP3, and FLAC cleaners perform bounded structural rewrites, reject protected provenance, and
  publish only when audio-bearing payload bytes remain identical;
- normal scanning is offline and has no telemetry.

High-severity parser, truncation, resource-limit, or discovery diagnostics make CLI automation exit
with code `3`; a zero-finding incomplete scan is never reported as clean. Git commands use bounded
stdout/stderr, clear repository-routing environment variables, disable interactive/lazy fetches,
and reject Git directories, object databases, or alternates that resolve outside the selected root.

`--in-place` is explicit, uses a temporary output and integrity gate, and creates a backup. Git
history rewriting and robust watermark defeat are outside the implemented remediation boundary.

Only the latest development revision receives security fixes until the first stable release.

## Third-party detectors

A plugin declares a capability manifest. A capability-guarded helper inspects it without importing
the module in the scanner process, and host policy then decides what may run. Detection is read-only,
so filesystem writes, process creation, and network access are denied by default even to a plugin
that requests them, and a refused plugin is reported rather than silently dropped.

By default `PluginIsolation.SUBPROCESS` runs each plugin in a separate interpreter. Fully trusted
in-process execution requires explicit selection. In subprocess mode:

- an exception/crash is separated from scanner state and a hang is terminated at its deadline;
- hard worker CPU and address-space limits are installed before plugin import through POSIX
  rlimits or a Windows Job Object; failure to install them rejects the helper;
- stdout/stderr are discarded and the response is size-checked before it is parsed;
- every returned finding is re-derived from its own evidence, so a plugin cannot forge a finding
  identity, reattribute a finding to another artifact, or impersonate another detector;
- sockets, process creation, and filesystem writes raise unless the matching capability was granted.

This is not a filesystem/system-call sandbox. The worker runs as the same user with the same
filesystem access as the host, and the in-worker guards are Python-level replacements that do not
stop native code or `ctypes`. Kernel CPU/memory quotas limit exhaustion but do not constrain file
access. Seccomp, AppContainer, or separately permissioned container isolation remains future work.
In both modes TrueAI verifies persistent file hashes and new discovered paths around scanning.

Audit certificates never assert human authorship. A `clear` status is bound to exact bytes and means
only that a complete scan found no indicator in its recorded scope. Unsigned certificates do not
authenticate their issuer; optional Ed25519 signatures do. Finite validity and issuer-signed,
finite-lifetime revocation lists are checked explicitly. A stale or unauthenticated list cannot
satisfy `--require-revocation-check`; sequence rollback still requires external state or a future
transparency service to detect.

Signed enterprise policy bundles are content-addressed, finite-lived, and Ed25519-authenticated.
They fail closed on a wrong key, changed claim, future issue time, or expiry. Suppressions and
exceptions never delete findings; their decisions are recorded in the report audit trail, and
protected provenance cannot be suppressed.

## Provenance verification

C2PA verification runs only when explicitly requested (dedicated verify or scan report attachment),
uses the reference implementation, and never
fetches a remote manifest unless the caller opts in. A correct signature from an unknown signer is
reported as `valid`, never as `trusted`; only chaining to an operator-configured trust anchor
establishes provenance.
