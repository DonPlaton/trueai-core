"""Verify the Linux confinement backend on a real Linux kernel.

Run inside a container:

    docker run --rm -v "$PWD:/work" -w /work python:3.12-slim \
        sh -c "pip install -q pydantic pathspec typer rich pyyaml \
               && python scripts/verify_linux_confinement.py"

Each check runs in a child process, because a seccomp filter that works kills the
child rather than returning an error. A parent that survived is not evidence; the
child's exit signal is. The checks that assert a *gap* matter as much as the ones
that assert a control: a documented gap that quietly closed would mean the
documentation is now wrong in the other direction.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))

CHILD = """
import sys
sys.path.insert(0, {repository!r})
from trueai.plugins.broker import BrokerGrants, NetworkGrant, SubprocessGrant
from trueai.plugins.confinement import ConfinementLevel, apply_confinement

grants = {grants}
report = apply_confinement(grants, ConfinementLevel.BEST_EFFORT)
if not report.applied:
    print("NOT-APPLIED", report.reason)
    raise SystemExit(97)
{body}
raise SystemExit(0)
"""


def child(grants: str, body: str) -> subprocess.CompletedProcess[bytes]:
    """Run one check in a fresh interpreter and return how it ended."""

    source = CHILD.format(repository=str(REPOSITORY), grants=grants, body=body)
    return subprocess.run(
        [sys.executable, "-c", source], capture_output=True, timeout=120, check=False
    )


def died_on_signal(result: subprocess.CompletedProcess[bytes]) -> bool:
    """Return whether the child was killed rather than exiting normally."""

    return result.returncode < 0 or result.returncode in {159, 137}


def main() -> int:
    from trueai.plugins.confinement import describe_platform

    available = describe_platform()
    print(
        f"platform: {available.platform} mechanism={available.mechanism} "
        f"available={available.available} reason={available.reason}"
    )
    if not available.available:
        print("FAIL: the Linux backend reports itself unavailable")
        return 1

    failures = 0

    print("\n[1] confinement applies and reports what it does not cover")
    result = child(
        "BrokerGrants()",
        "\n".join(
            [
                "print('APPLIED')",
                "for line in report.established: print('  established:', line[:100])",
                "for line in report.not_enforced: print('  not enforced:', line[:100])",
            ]
        ),
    )
    if b"APPLIED" not in result.stdout:
        print(f"FAIL: {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print(result.stdout.decode().rstrip())

    print("\n[2] an ungranted socket kills the process")
    result = child("BrokerGrants()", "import socket; socket.socket(); print('OPENED')")
    if b"OPENED" in result.stdout or not died_on_signal(result):
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print(f"  ok (killed, rc={result.returncode})")

    print("\n[3] a granted endpoint leaves sockets usable")
    result = child(
        "BrokerGrants(network=NetworkGrant(endpoints=(('example.test', 443),)))",
        "import socket; socket.socket(); print('OPENED')",
    )
    if b"OPENED" not in result.stdout:
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print("  ok")

    print("\n[4] running a different program is killed when exec is not granted")
    result = child(
        "BrokerGrants()",
        "import os, sys\nos.execv(sys.executable, [sys.executable, '-c', 'print(1)'])",
    )
    if not died_on_signal(result):
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print(f"  ok (killed, rc={result.returncode})")

    print("\n[4b] a granted executable can still be run")
    result = child(
        "BrokerGrants(subprocess=SubprocessGrant(executables=('/bin/true',)))",
        "import subprocess\nsubprocess.run(['/bin/true'], check=True)\nprint('RAN')",
    )
    if b"RAN" not in result.stdout:
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print("  ok")

    print("\n[4c] forking a copy of the worker is NOT blocked, exactly as documented")
    result = child(
        "BrokerGrants()",
        "\n".join(
            [
                "import os",
                "if os.fork() == 0:",
                "    os._exit(0)",
                "os.wait()",
                "print('FORKED-AS-DOCUMENTED')",
            ]
        ),
    )
    if b"FORKED-AS-DOCUMENTED" not in result.stdout:
        print(f"FAIL: the documented gap did not behave as documented: rc={result.returncode}")
        failures += 1
    else:
        print("  ok (documented gap: clone is shared with threading)")

    print("\n[5] threads still work: clone is deliberately not filtered")
    result = child(
        "BrokerGrants()",
        "import threading\nt = threading.Thread(target=lambda: None)\nt.start()\n"
        "t.join()\nprint('THREADED')",
    )
    if b"THREADED" not in result.stdout:
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print("  ok")

    print("\n[6] ptrace is denied even when everything else is granted")
    result = child(
        "BrokerGrants(network=NetworkGrant(endpoints=(('a.test', 1),)), "
        "subprocess=SubprocessGrant(executables=('/bin/true',)))",
        "import ctypes\nctypes.CDLL(None).ptrace(0, 0, 0, 0)\nprint('TRACED')",
    )
    if b"TRACED" in result.stdout or not died_on_signal(result):
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print(f"  ok (killed, rc={result.returncode})")

    print("\n[7] ordinary file reads keep working under the filter")
    result = child(
        "BrokerGrants()",
        "print('READ', len(open('/etc/hostname', 'rb').read()) >= 0)",
    )
    if b"READ" not in result.stdout:
        print(f"FAIL: rc={result.returncode} {result.stdout!r} {result.stderr[-600:]!r}")
        failures += 1
    else:
        print("  ok")

    print(f"\n{'FAILED' if failures else 'PASSED'}: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
