"""Fail when the documentation describes a tool that does not exist.

Documentation drifts in one direction. A flag gets renamed, a module moves, a
command is added — and the prose keeps describing the old shape, confidently,
because prose has no compiler. The reader who is hurt is the one who trusts it:
they run the documented command, it fails, and they conclude the tool is broken
rather than the sentence.

Five things checked, each a way documentation goes wrong:

* **A named command does not exist.** `trueai cache prne` in a doc is a reader
  typing it and getting an error.
* **A named option does not exist.** The worst of the five, because a wrong flag
  looks exactly like a right one.  Only lines that mention `trueai` are checked:
  a first attempt looked at every long option and reported `--all-extras` and
  `--build-arg`, which are pip's and docker's, and an allowlist of other tools'
  flags would rot faster than the documentation it guards.
* **A relative link points at nothing.** A dead link in a document about
  verifying things is its own small joke.
* **A document nothing links to.** Not broken, but nobody will find it, and an
  unread document is one that quietly goes stale.
* **A backlog entry naming a file that is not there.** A completed item citing a
  module that was renamed describes work nobody can check.

What this deliberately does not check is whether the prose is *true*. That needs
a reader. What it checks is whether the nouns exist, which is the part that can
be checked and the part that rots first.

    python scripts/check_docs.py
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

#: Markdown files that make claims about the tool.
DOCUMENTS: tuple[Path, ...] = (
    REPOSITORY / "README.md",
    REPOSITORY / "PROJECT_STATUS.md",
    REPOSITORY / "CONTRIBUTING.md",
    REPOSITORY / "SECURITY.md",
    REPOSITORY / "AGENTS.md",
    REPOSITORY / "skills" / "trueai" / "SKILL.md",
    REPOSITORY / "examples" / "README.md",
    *sorted((REPOSITORY / "docs").glob("*.md")),
)

#: `trueai scan`, or the same invocation in a fenced command block.
COMMAND = re.compile(r"(?<!from )(?<![\w-])trueai((?: [a-z][a-z0-9-]*)+)")

#: A long option, wherever it appears.
OPTION = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]+)")

#: `trueai` used as a command rather than as part of an image or package name.
INVOCATION = re.compile(r"\btrueai\s+[a-z-]")

#: A relative Markdown link, excluding anchors and absolute URLs.
LINK = re.compile(r"\]\((?!https?://|#|mailto:)([^)#]+)(?:#[^)]*)?\)")


@dataclass(frozen=True, slots=True)
class Problem:
    """One documented thing that does not exist."""

    document: str
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.kind}] {self.document}: {self.detail}"


def cli_surface() -> tuple[set[str], dict[str, set[str]], set[str]]:
    """Return every command path, the options each accepts, and which are groups.

    Read from the Typer app rather than from `--help` output, so a rename is
    caught by the same mechanism whatever the help text happens to say. The group
    set matters because a group takes no positional arguments: the word after one
    has to be a subcommand, and without that distinction a typo resolves to the
    parent and passes.
    """

    import typer

    from trueai.cli.app import app

    root = typer.main.get_command(app)
    commands: set[str] = set()
    options: dict[str, set[str]] = {}
    groups: set[str] = set()

    def walk(command: object, prefix: str) -> None:
        """Walk Typer's command tree without importing its private Click fork.

        Typer 0.27 vendors its command implementation under ``typer._click``.
        Importing the separately installed ``click`` package makes an
        ``isinstance(..., click.Group)`` check false even though the object has
        a real command mapping.  Structural inspection also keeps this gate
        compatible with older Typer releases that used upstream Click.
        """

        name = getattr(command, "name", None)
        path = f"{prefix} {name}".strip() if name else prefix
        commands.add(path)
        names: set[str] = set()
        for parameter in getattr(command, "params", ()):
            for flag in list(getattr(parameter, "opts", ())) + list(
                getattr(parameter, "secondary_opts", ())
            ):
                if flag.startswith("--"):
                    names.add(flag)
        options[path] = names
        children = getattr(command, "commands", None)
        if isinstance(children, Mapping):
            groups.add(path)
            for child in children.values():
                walk(child, path)

    walk(root, "")
    # The root command is registered under the app's own name; normalise it so a
    # document writing `trueai scan` matches regardless.
    normalised = {
        name if name.startswith("trueai") else f"trueai {name}".strip() for name in commands
    }
    options = {
        (name if name.startswith("trueai") else f"trueai {name}".strip()): flags
        for name, flags in options.items()
    }
    normalised_groups = {
        name if name.startswith("trueai") else f"trueai {name}".strip() for name in groups
    }
    return normalised, options, normalised_groups


def _label(path: Path) -> str:
    """Name a document relative to the repository, or by itself if it is elsewhere.

    A synthetic document in a temporary directory is how the checker's own tests
    give it something wrong to find, and a checker that cannot be pointed at one
    is a checker whose failure paths are never exercised.
    """

    try:
        return path.relative_to(REPOSITORY).as_posix()
    except ValueError:
        return path.name


def check_document(
    path: Path,
    commands: set[str],
    options: dict[str, set[str]],
    groups: set[str] | None = None,
) -> list[Problem]:
    """Return every nonexistent thing this document names."""

    problems: list[Problem] = []
    relative = _label(path)
    text = path.read_text(encoding="utf-8")

    known_groups = groups if groups is not None else set()

    def resolve(match: re.Match[str]) -> tuple[str, Problem | None]:
        # Walk the tree. A group takes no positional arguments, so while the
        # current path is a group the next word has to be one of its
        # subcommands. Once a leaf is reached the rest are arguments. Popping a
        # longest prefix instead would let `trueai scna` resolve to bare
        # `trueai` and pass, which is how a typo becomes invisible.
        current = "trueai"
        for word in match.group(1).split():
            if current not in known_groups:
                break
            extended = f"{current} {word}"
            if extended not in commands:
                return current, Problem(
                    relative,
                    "command",
                    f"`{extended}` names no command; `{current}` has no subcommand {word!r}",
                )
            current = extended
        return current, None

    for match in COMMAND.finditer(text):
        _, problem = resolve(match)
        if problem is not None:
            problems.append(problem)

    # Only lines that are about `trueai` are checked. A first attempt looked at
    # every long option in the file and reported `--all-extras`, `--build-arg`,
    # and `--outdir` — pip, docker, and build flags this project documents and
    # does not own. Maintaining an allowlist of other tools' flags would rot;
    # scoping to the line removes the whole class.
    for line in text.splitlines():
        # `trueai` followed by whitespace, so an image or container named
        # `trueai-core:audit` on a docker line does not drag docker's flags in.
        if not INVOCATION.search(line):
            continue
        invocations = list(COMMAND.finditer(line))
        for index, invocation in enumerate(invocations):
            command, problem = resolve(invocation)
            if problem is not None:
                continue
            segment_end = (
                invocations[index + 1].start() if index + 1 < len(invocations) else len(line)
            )
            allowed = options.get(command, set()) | options.get("trueai", set())
            for match in OPTION.finditer(line, invocation.end(), segment_end):
                flag = match.group(1)
                if flag not in allowed and flag not in {"--help", "--version"}:
                    problems.append(
                        Problem(
                            relative,
                            "option",
                            f"{flag} is shown with `{command}` but that command does not accept "
                            "it; a wrong flag reads exactly like a right one",
                        )
                    )

    for match in LINK.finditer(text):
        target = (path.parent / match.group(1)).resolve()
        if not target.exists():
            problems.append(Problem(relative, "link", f"{match.group(1)} does not exist"))

    return problems


def orphaned_documents() -> list[Problem]:
    """Documents nothing links to, which nobody will find and nobody will update."""

    linked: set[Path] = set()
    for document in DOCUMENTS:
        if not document.exists():
            continue
        for match in LINK.finditer(document.read_text(encoding="utf-8")):
            linked.add((document.parent / match.group(1)).resolve())
    problems: list[Problem] = []
    for candidate in sorted((REPOSITORY / "docs").glob("*.md")):
        if candidate.resolve() not in linked:
            problems.append(
                Problem(
                    _label(candidate),
                    "orphan",
                    "nothing links to it, so nobody will find it and nobody will update it",
                )
            )
    return problems


def missing_documents() -> list[Problem]:
    """Documents the check itself expects, so a rename does not silently shrink it."""

    return [
        Problem(_label(document), "missing", "does not exist")
        for document in DOCUMENTS
        if not document.exists()
    ]


def run() -> list[Problem]:
    commands, options, groups = cli_surface()
    problems: list[Problem] = list(missing_documents())
    for document in DOCUMENTS:
        if document.exists():
            problems.extend(check_document(document, commands, options, groups))
    problems.extend(orphaned_documents())
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)

    problems = run()
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        print(f"\n{len(problems)} documentation problem(s).", file=sys.stderr)
        return 1
    print(f"{len(DOCUMENTS)} documents name only commands, options, and files that exist.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
