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

## Operating-system confinement

The broker is a contract and the guards enforce it against ordinary Python.
Neither stops native code, `ctypes`, or a plugin that restores the functions the
guards replaced. `trueai/plugins/confinement.py` asks the kernel instead.

```bash
trueai scan ./repo --plugin-confinement best_effort   # default
trueai scan ./repo --plugin-confinement required      # refuse to run unconfined
trueai scan ./repo --plugin-confinement none
```

| Level | Behaviour |
|---|---|
| `none` | No kernel confinement. The guards still apply. |
| `best_effort` | Default. Apply what the platform offers and record every gap. |
| `required` | Refuse to run a plugin when confinement cannot be established. |

`required` exists because silently degrading to "we tried" is indistinguishable,
from the report, from having succeeded. Availability is a property of the
machine, not of the code: unprivileged user namespaces are disabled on some
distributions, and a container policy can block `seccomp`. The level is how an
operator says which outcome they want when that happens.

### Linux — seccomp and namespaces

Applied by the worker to itself, before the plugin is imported, because import
time is when a hostile plugin acts.

- `PR_SET_NO_NEW_PRIVS`, so nothing the worker starts can gain privileges.
- `unshare(CLONE_NEWUSER | CLONE_NEWNET)` when `network` is not granted: an empty
  network namespace is a stronger statement than filtering socket syscalls,
  because there is no route left to filter against.
- A seccomp BPF filter that **kills the process** on a denied syscall. Returning
  `EPERM` would let a plugin retry through another spelling; a dead worker is a
  diagnostic the host already knows how to report.

The filter is derived from the grants. Without `network`: `socket`, `connect`,
`bind`, `listen`, `accept`, `sendto`, `recvfrom`. Without `run_subprocess`:
`execve`, `execveat`. Always: `ptrace`.

**`fork` and `vfork` are deliberately absent.** glibc has routed `os.fork()`
through `clone` for years, and `clone` is shared with threading — filtering it
would stop the interpreter rather than the plugin. Denying `fork` by number would
have looked like a control and been none, so the gap is recorded instead:
*running a different program is blocked; duplicating this one is not.*

Syscall numbers are pinned for `x86_64` and `aarch64` only. On any other
architecture the mechanism reports itself unavailable, because a filter built
from guessed numbers denies the wrong calls.

A **mount namespace** makes the whole filesystem read-only, then re-opens exactly
the granted paths: the scratch directory, and the one the worker writes its
protocol response into. A worker that cannot answer the host is not confined, it
is broken. The user namespace is what makes this possible unprivileged — inside
it the process holds `CAP_SYS_ADMIN`, which is what mounting requires — and the
real uid and gid are mapped to themselves so every ownership check answers as it
did outside.

This is **write** confinement, not read confinement. Reads still reach anything
the user can read, because a worker that cannot read the interpreter and its
dependencies cannot start. Hiding the filesystem would need `pivot_root` into a
per-invocation tree, which is not implemented and is named as a gap rather than
implied away.

Supplementary groups are dropped by the user namespace, so a file readable only
through one of them becomes unreadable to the plugin. That is a real behaviour
change and it is in the report.

### Windows — a restricted token

Windows has no `seccomp`, and a process cannot narrow its own token once it is
running. The restriction is therefore chosen when the worker is **spawned**, in
`trueai/plugins/windows_token.py`, through `CreateRestrictedToken` and
`CreateProcessAsUserW`:

- every privilege the host token holds is dropped (`DISABLE_MAX_PRIVILEGE`);
- `BUILTIN\Administrators` becomes deny-only, which is stronger than absent —
  an absent group can be re-added, a deny-only entry cannot.

`subprocess` cannot pass a token, so the process is created through the Win32 API
directly. That is affordable only because the protocol is already file-based:
request in, response out, plugin stdout and stderr discarded. No pipes to plumb.

**This is not AppContainer.** There is no filesystem isolation and no network
isolation; a restricted token does not stop a plugin reading anything the user
can read. AppContainer would need a profile, a SID, and ACLs on the artifact and
the scratch directory, and it is not implemented. The report says all of this
rather than reporting "confined".

### macOS — sandbox_init

A generated SBPL profile: deny by default, then re-allow exactly what a grant
covers. The scratch directory is the only writable location and it is named
rather than implied.

Reads are allowed broadly, because a worker that cannot read the interpreter and
its dependencies cannot start and enumerating them is not something a scanner can
do reliably. `sandbox_init` has been deprecated by Apple for years while remaining
the only interface a process has to sandbox itself; that is stated here rather
than discovered later.

## Adversarial tests: hostile *native* plugins

The Python guards replace functions; native code goes around them. So the
adversarial tests reach the operating system through `ctypes`, on both POSIX and
Windows — a "native" plugin that only worked on one would test one platform's
confinement and quietly skip the other.

`scripts/verify_native_plugins.py` runs them through the **whole real path**:
entry point, manifest review, worker spawn, confinement, guards, and the host's
deadline.

| Attempt | Linux | Windows |
|---|---|---|
| Write outside the grant | **refused** (read-only mount namespace) | not confined |
| Write into the scratch grant | allowed | allowed |
| Open a socket | **process killed** (seccomp) | not confined |
| Start another program | **process killed** (seccomp) | not confined |
| Outlive the deadline | **killed by the host** | **killed by the host** |
| Read outside the grant | not confined | not confined |

Every "not confined" cell is asserted by a test, not left implicit. On Windows
`test_windows_does_not_stop_a_native_write_and_says_so` fails the day Windows
filesystem confinement is implemented, which is the point: the claim in the docs
and the behaviour move together.

The script also carries **negative controls**. Check [7] runs the same native
writer with `--plugin-confinement none` and requires the write to land; check [8]
does the same for the socket. Without them, a check that passes because the
attempt would have failed anyway is indistinguishable from a check that passes
because confinement worked.

```bash
docker run --rm --security-opt seccomp=unconfined -v "$PWD:/work" -w /work \
    python:3.12-slim sh -c "pip install -q pydantic pathspec typer rich pyyaml \
    && python scripts/verify_native_plugins.py"
```

`seccomp=unconfined` is needed because Docker's own filter blocks the `unshare`
this confinement depends on. The machine it protects is a developer's, not a
container.

### How this is verified

- **Linux**: `scripts/verify_linux_confinement.py` for the mechanism and
  `scripts/verify_native_plugins.py` for the whole path, both run inside a
  container against a real kernel. A denied syscall must *kill the child* — a
  parent that survived is not evidence. Both scripts also assert the documented
  **gaps**: threads still start, a granted executable still runs, forking a copy
  of the worker is still possible, and reads outside the grant still succeed. A
  gap that quietly closed would mean the documentation is now wrong in the other
  direction.
- **Windows**: a test compares the privilege count of an ordinary child with a
  restricted one. An "applied" flag proves nothing; a privilege count does.
- **macOS**: unverified. There is no macOS machine in this project's CI, and the
  backend is marked as such rather than presented as tested.

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

System-call filtering and write confinement are implemented on Linux; see
[operating-system confinement](#operating-system-confinement) for what each platform does and does
not enforce, and [adversarial tests](#adversarial-tests-hostile-native-plugins) for the evidence.
**Read** confinement is not implemented anywhere, and on Windows neither reads, writes, sockets,
nor process creation are confined natively — a restricted token is not AppContainer. Process
isolation, kernel quotas, seccomp, the mount namespace, and the Python guards are defense in depth;
where a platform does not enforce something, that is stated rather than covered by the phrase.

Both isolation modes are equally subject to the engine's existing checks: artifact
hashes and directory inventories are re-examined after detectors run, and any
persistent mutation fails the scan's integrity status.

## Compatibility

A manifest declares which report schema versions it produces findings for. A plugin
built against a schema this host does not emit is refused with an explicit reason
rather than allowed to emit findings a consumer cannot parse. See
[schema compatibility](schema-compatibility.md).
