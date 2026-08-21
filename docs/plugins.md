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

## Capabilities

| Capability | Meaning |
|---|---|
| `read_artifact` | Read the artifact under inspection. |
| `read_workspace` | Read files near the artifact, such as sibling parts of a package. |
| `write_filesystem` | Write anywhere on the filesystem. |
| `run_subprocess` | Start other processes. |
| `network` | Open network connections. |

Detection is a read-only activity, so the default host policy grants only
`read_artifact` and `read_workspace`. A plugin that declares `network` is refused
by default rather than silently downgraded, and the refusal appears in the scan
report as a `plugin_rejected` diagnostic so an operator can see that coverage was
reduced.

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
| `in_process` | Plugins load into the scanner process. Fast, and fully trusting. The default, for compatibility. |
| `subprocess` | Each plugin runs in a separate interpreter with capability guards and a deadline. |
| `disabled` | Third-party detectors are not loaded at all. |

## What subprocess isolation actually guarantees

- **Crashes are contained.** A plugin that raises, segfaults, or allocates without
  bound takes down its worker, not the scan. The failure becomes a diagnostic.
- **Hangs end.** The worker is killed at its deadline and reported as
  `plugin_timeout`.
- **Output is bounded.** The response is a size-checked file, so a plugin cannot
  exhaust host memory by returning too much.
- **Findings cannot be asserted into existence.** Every returned finding is
  re-derived from its own evidence. A plugin cannot forge a finding identity
  (`plugin_forged_finding_id`), attribute a finding to another artifact
  (`plugin_artifact_mismatch`), or impersonate another detector
  (`plugin_impersonation`). A plugin that mutates the artifact while running is
  caught by re-hashing (`plugin_mutated_artifact`).
- **Ungranted capabilities fail loudly.** Inside the worker, sockets, process
  creation, and filesystem writes are replaced with functions that raise when the
  matching capability was not granted.

## What it does not guarantee

The worker runs as the same operating-system user with the same filesystem access
as the host. The in-worker guards are Python-level replacements: they stop an
ordinary plugin, and they do not stop native code, `ctypes`, or a plugin that
deliberately restores the functions that were replaced.

A real sandbox — seccomp, AppContainer, or container-level isolation — is future
work. Until it exists, `subprocess` isolation should be read as "contains accidents
and catches dishonest output", not "safely runs hostile code".

Both isolation modes are equally subject to the engine's existing checks: artifact
hashes and directory inventories are re-examined after detectors run, and any
persistent mutation fails the scan's integrity status.

## Compatibility

A manifest declares which report schema versions it produces findings for. A plugin
built against a schema this host does not emit is refused with an explicit reason
rather than allowed to emit findings a consumer cannot parse. See
[schema compatibility](schema-compatibility.md).
