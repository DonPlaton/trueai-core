# Third-party detectors: manifests, capabilities, and isolation

A plugin is ordinary Python running inside a forensic tool. That is a position an
attacker would like to occupy, and it is also a position an ordinary buggy library
can occupy by accident. The plugin host addresses both.

## Writing a plugin

Expose a detector through the `trueai.detectors` entry-point group:

```toml
[project.entry-points."trueai.detectors"]
acme-invoices = "acme_trueai.detectors:registration"
```

The entry point may return a detector, a zero-argument factory, or a
`PluginRegistration` carrying a capability manifest. Only the last form lets a host
decide about the plugin before trusting it:

```python
from trueai.plugins import PluginCapability, PluginManifest, PluginRegistration

registration = PluginRegistration(
    manifest=PluginManifest(
        detector_id="acme.invoice-forensics.v1",
        name="ACME invoice forensics",
        version="2.1.0",
        vendor="acme",
        description="Inspects invoice templates for tooling residue.",
        capabilities=frozenset({PluginCapability.READ_ARTIFACT}),
        compatible_schema_versions=frozenset({"0.1"}),
    ),
    factory=InvoiceDetector,
)
```

A plugin without a manifest still runs under the default policy, but the host
records a *synthesized* manifest for it, marked `declared=False`, and treats it as
requesting read-only artifact access.

Shipping a `PluginRegistration` is what lets a host decide about a plugin without
building it. A bare factory function's identity is only knowable by calling it, so
it is constructed before the policy can weigh in.

## Capabilities

| Capability | Meaning | Scope it carries |
|---|---|---|
| `read_artifact` | Read the artifact under inspection. | Exactly one file. |
| `read_workspace` | Read files near the artifact. | One directory subtree. |
| `write_temporary` | Write scratch output. | A host-owned directory with a byte budget. |
| `write_filesystem` | Write anywhere on the filesystem. | None. |
| `run_subprocess` | Start other processes. | An executable allowlist. |
| `network` | Open outbound connections. | A `(host, port)` allowlist. |
| `load_native_library` | Load native code. | Named libraries, explicitly unmediated. |

Detection is a read-only activity, so the default host policy grants only
`read_artifact` and `read_workspace`. A plugin that declares `network` is refused
by default rather than silently downgraded, and the refusal appears in the scan
report as a `plugin_rejected` diagnostic so an operator can see that coverage was
reduced.

## The capability broker

A boolean capability answers "may this plugin write files?" The useful question
is "may it write *this* file, *here*, for the duration of *this* scan?" A grant
that cannot express its scope has to be granted at its widest, which is how
`write_filesystem` ends up meaning "anywhere the user can write".

The broker is the contract that replaces boolean permission with mediated access.
A plugin declares `bind_broker` and receives one:

```python
from trueai.detectors.base import BaseDetector

class InvoiceDetector(BaseDetector):
    id = "acme.invoice-forensics.v1"

    def bind_broker(self, broker):
        self.broker = broker

    def scan(self, artifact, context):
        payload = self.broker.read_artifact()          # the granted file, read-only
        sibling = self.broker.read_workspace("meta.xml")  # inside the grant, or refused
        if self.broker.granted(PluginCapability.WRITE_TEMPORARY):
            with self.broker.open_temporary("work.bin") as handle:
                handle.write(payload[:1024])           # charged against the budget
        ...
```

Each grant carries its own scope, and the broker is the single place the scope is
checked:

- **`ArtifactGrant`** — one path and the digest the host will re-check afterwards.
  Not a directory, not a glob.
- **`WorkspaceGrant`** — one root. Paths are resolved before the prefix check, so
  `../../etc/passwd` and an absolute path are both refused; a per-file size cap
  keeps one read from becoming a memory-exhaustion primitive.
- **`TemporaryOutputGrant`** — a directory the host creates and removes around a
  single invocation, with a byte budget charged across *every* write. A per-file
  limit is not a limit when a plugin can open more files, and a budget checked at
  close is a budget an attacker writes past, so a refused write never reaches the
  file.
- **`NetworkGrant`** — a `(host, port)` allowlist. There is no "network: yes":
  a forensic tool that can reach an arbitrary host is an exfiltration path with a
  scan attached. A grant with no endpoints is a construction error, not an
  implicit "everything".
- **`SubprocessGrant`** — named executables, resolved before comparison, run with
  `shell=False`.
- **`NativeLibraryGrant`** — named libraries, and it must set
  `acknowledged_unmediated=True`. The broker cannot mediate native code; this
  grant makes it declared rather than contained, so an operator who denies it
  knows every remaining plugin is one the guards can actually govern.

Every refusal raises `CapabilityDeniedError` carrying the capability and the
scope, and the message names the capability even when the caller's text did not.
"Outside the grant" leaves an operator guessing which grant to widen.

### What the broker is not

It is a contract, not a jail. A plugin can still call `open()` directly; the
guards in `trueai/plugins/guards.py` catch the documented spellings, and `PLUG-02`
adds operating-system confinement underneath. What the broker buys before then is
real anyway: a grant can be *narrow*, a refusal is attributable, and a plugin
written against the broker keeps working unchanged when ambient authority is taken
away, because it never depended on it.

The broker is opt-in. A detector that does not declare `bind_broker` behaves
exactly as it did before.

## Host policy

```python
from trueai import TrueAIEngine
from trueai.plugins import CapabilityPolicy, PluginCapability, PluginIsolation

policy = CapabilityPolicy(
    granted=frozenset({PluginCapability.READ_ARTIFACT}),
    require_manifest=True,                       # refuse plugins that will not declare
    allowed_detector_ids=frozenset({"acme.invoice-forensics.v1"}),
)
engine = TrueAIEngine.default(
    plugin_isolation=PluginIsolation.SUBPROCESS,
    capability_policy=policy,
)
```

`require_manifest=True` is the enterprise posture: a plugin that will not say what
it needs does not run.

Review what is installed and what the host decided:

```bash
trueai plugins list
trueai scan ./repo --plugins subprocess
trueai scan ./repo --plugins disabled
```

## Isolation modes

| Mode | Behaviour |
|---|---|
| `in_process` | Plugins load into the scanner process. Fast, fully trusting, and available only by explicit selection. |
| `subprocess` | Default. Manifest inspection and each detector run use separate interpreters with capability guards and a deadline. |
| `disabled` | Third-party detectors are not loaded at all. |

## What subprocess isolation actually guarantees

- **Host state is separated.** A plugin exception or crash takes down its worker,
  not the scanner process. The failure becomes a diagnostic.
- **Hangs end.** The worker is killed at its deadline and reported as
  `plugin_timeout`.
- **CPU and memory are bounded before import.** The helper installs hard kernel limits before
  loading plugin code: RLIMIT_AS/RLIMIT_CPU on POSIX and a per-process Windows Job Object on
  Windows. Failure to install a configured limit rejects the plugin instead of weakening the
  boundary.
- **Output is bounded.** stdout and stderr are discarded, and the response is a
  size-checked file, so a plugin cannot exhaust host memory by printing or returning too much.
- **Findings cannot be asserted into existence.** Every returned finding is
  re-derived from its own evidence. A plugin cannot forge a finding identity
  (`plugin_forged_finding_id`), attribute a finding to another artifact
  (`plugin_artifact_mismatch`), or impersonate another detector
  (`plugin_impersonation`). A plugin that mutates the artifact while running is
  caught by re-hashing (`plugin_mutated_artifact`).
- **Ungranted capabilities fail loudly.** Inside the worker, sockets, process
  creation, and filesystem writes are replaced with functions that raise when the
  matching capability was not granted.

## When the guards apply

The manifest inspector and scan worker install guards before importing the plugin,
so module-level code and constructors are covered too. The scanner process does not
import a plugin merely to discover its manifest. Import-time side effects are a
plugin defect and fail with a message naming the denied capability.

Every documented way to write a file is covered: `open`, `io.open`, `Path.open`,
`os.open`, and the `os`, `shutil`, and `Path` mutators. Reads are unaffected.

## What it does not guarantee

The worker runs as the same operating-system user with the same filesystem access
as the host. The in-worker guards are Python-level replacements: they stop an
ordinary plugin, and they do not stop native code, `ctypes`, or a plugin that
deliberately restores the functions that were replaced.

Kernel quotas bound worker memory and CPU time; they do not restrict which files native code can
open or which system calls it can make. POSIX CPU limits apply per process. A plugin explicitly
granted subprocess capability can therefore create children with their own inherited per-process
budgets. On Windows, children remain in the Job Object unless a stricter external host changes that
policy.

A plugin whose id collides with one that is already registered is refused and
reported rather than aborting discovery, so an installed package cannot stop the
tool from starting.

A filesystem/system-call sandbox such as seccomp, AppContainer, or a separately permissioned
container remains future work. Process isolation, kernel quotas, and Python guards are defense in
depth; they are not described as protection against malicious native code.

Both isolation modes are equally subject to the engine's existing checks: artifact
hashes and directory inventories are re-examined after detectors run, and any
persistent mutation fails the scan's integrity status.

## Compatibility

A manifest declares which report schema versions it produces findings for. A plugin
built against a schema this host does not emit is refused with an explicit reason
rather than allowed to emit findings a consumer cannot parse. See
[schema compatibility](schema-compatibility.md).
