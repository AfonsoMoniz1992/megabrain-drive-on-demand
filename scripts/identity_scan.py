#!/usr/bin/env python3
"""Identity scan — the publish gate for this repository.

Design rule: the gate must not be able to pass while hiding something, and every
claim made about it must be reproducible from its output.

Algorithm (the reason this is not a shell script): every candidate text is
matched against every detector pattern with full match spans, and each match is
classified by whether its whole span is covered by a declared exemption:

    fully covered      -> EXEMPT (declared, printed with its justification)
    partially covered  -> HIT    (an exemption may not hide part of a value)
    not covered        -> HIT

That removes whole classes of bypass that a mask-and-recheck approach cannot
close: truncation, ordering, partial overlap, and regex delimiters inside the
patterns. Nothing is truncated before analysis; truncation happens only when
printing.

Surfaces scanned, all five:

    1. the working tree: file contents (whole lines) and file/directory names;
    2. every reachable commit and blob in the history, including paths;
    3. every commit message and every annotated tag message;
    4. the Git identity metadata: author, committer and tagger names and addresses;
    5. the release artefacts on disk (main.js, manifest.json, styles.css).

Detectors:

    * built-in generic patterns: tailnet domains, RFC1918 addresses, consumer
      mailboxes, Google OAuth client ids, Drive links, service accounts;
    * $IDENTITY_DENYLIST, one regex per line, kept OUTSIDE the tree. An
      authoritative run REQUIRES it, with at least one usable pattern; every
      pattern must compile. Missing, empty, comment-only or invalid deny-lists
      fail the run instead of passing it. IDENTITY_ALLOW_NO_DENYLIST=1 permits a
      smoke run that reports itself as non-authoritative.

Declared exemptions: $IDENTITY_EXEMPTIONS (default
scripts/identity-exemptions.txt), `regex :: justification`. A line without a
justification fails the run. Exemptions never apply to surface 4 except as
explicitly reported KNOWN exceptions, which change the verdict to
PASS_WITH_DECLARED_EXCEPTIONS so a plain PASS can never hide one.

Strict mode: IDENTITY_REQUIRE_NO_EXEMPTIONS=1 fails when an exemption is used,
when one is declared, or when a known identity exception exists, and prints each
reason — including when the run stops early for a missing deny-list.

Verdicts: PASS (nothing found, nothing declared, nothing used),
PASS_WITH_DECLARED_EXCEPTIONS (only declared exceptions), FAIL.

Exit status: 0 for PASS and PASS_WITH_DECLARED_EXCEPTIONS, 1 for FAIL,
2 for a configuration error (no usable deny-list, invalid pattern).

Usage: scripts/identity_scan.py [repo-path]
Self-test: scripts/identity-scan-selftest.sh
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SELF_REL_PATH = "scripts/identity_scan.py"
EXCLUDED_DIRS = {".git", "node_modules"}
ARTEFACTS = ("main.js", "manifest.json", "styles.css")
DISPLAY_LIMIT = 200

BUILTIN_PATTERNS = (
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*\.ts\.net",
    r"[A-Za-z0-9-]+\.ts\.net",
    r"\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b",
    r"\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b",
    r"\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b",
    r"[A-Za-z0-9._%+-]+@(gmail|googlemail|icloud|me|outlook|hotmail|live|proton|protonmail|yahoo)\.[A-Za-z]{2,}",
    r"[0-9]{6,}-[a-z0-9]{12,}\.apps\.googleusercontent\.com",
    r"drive\.google\.com/(drive/)?(folders|file)/",
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com",
)


@dataclass
class Exemption:
    pattern: re.Pattern
    justification: str


@dataclass
class Report:
    enforced: list[str] = field(default_factory=list)
    exempted: list[str] = field(default_factory=list)
    known_identity: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    configuration_errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "enforced_hits": len(self.enforced),
            "exempted_hits": len(self.exempted),
            "known_identity_exceptions": len(self.known_identity),
            "configuration_errors": len(self.configuration_errors),
        }


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        errors="replace",
    )
    return result.stdout if result.returncode == 0 else ""


def git_objects(repo: Path) -> tuple[list[str], dict[str, str]]:
    """Reachable object ids in traversal order, with the first path seen for each."""
    order: list[str] = []
    paths: dict[str, str] = {}
    for line in run_git(repo, "rev-list", "--objects", "--all").splitlines():
        sha, _, path = line.partition(" ")
        if not sha:
            continue
        if sha not in paths:
            order.append(sha)
            paths[sha] = path
    return order, paths


def batch_objects(repo: Path, shas: list[str]) -> list[tuple[str, str, bytes]]:
    """Read objects in one `git cat-file --batch` pass: (sha, type, payload).

    Content is read as bytes and decoded here rather than pre-filtered by
    `git grep -E`, because a pattern that is valid for the matching engine may be
    invalid — or behave differently — as a POSIX extended regex. Filtering in
    Python keeps one matching semantics for every surface.
    """
    if not shas:
        return []
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input="\n".join(shas).encode(),
        capture_output=True,
    )
    data = proc.stdout
    objects: list[tuple[str, str, bytes]] = []
    position = 0
    while position < len(data):
        header_end = data.find(b"\n", position)
        if header_end == -1:
            break
        header = data[position:header_end].decode("utf-8", "replace").split()
        position = header_end + 1
        if len(header) != 3:
            # "<sha> missing" or a truncated entry: stop rather than misparse.
            break
        sha, kind, size = header[0], header[1], int(header[2])
        payload = data[position:position + size]
        position += size + 1     # object payload is followed by a newline
        objects.append((sha, kind, payload))
    return objects


def object_message(payload: bytes) -> str:
    """The message part of a commit or annotated tag object."""
    text = payload.decode("utf-8", "replace")
    _, separator, message = text.partition("\n\n")
    return message if separator else ""


def load_denylist(patterns: list[re.Pattern], report: Report) -> bool:
    """Returns True when the run is authoritative."""
    path = os.environ.get("IDENTITY_DENYLIST", "").strip()
    allow_missing = os.environ.get("IDENTITY_ALLOW_NO_DENYLIST", "0") == "1"
    if not path:
        if allow_missing:
            report.notes.append("denylist=<none> (non-authoritative run: IDENTITY_ALLOW_NO_DENYLIST=1)")
            return False
        report.configuration_errors.append(
            "no deny-list: set IDENTITY_DENYLIST to the out-of-tree file, or "
            "IDENTITY_ALLOW_NO_DENYLIST=1 for a smoke run"
        )
        return False
    candidate = Path(path)
    if not candidate.is_file():
        report.configuration_errors.append(f"deny-list is not a readable file: {path}")
        return False
    try:
        raw = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError as error:  # pragma: no cover - defensive
        report.configuration_errors.append(f"deny-list could not be read: {error}")
        return False

    usable = 0
    for number, line in enumerate(raw.splitlines(), start=1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            patterns.append(re.compile(entry))
        except re.error as error:
            report.configuration_errors.append(f"invalid deny-list pattern on line {number}: {error}")
            continue
        usable += 1
    if usable == 0:
        report.configuration_errors.append(
            "deny-list has no usable pattern (empty, comments only, or all patterns invalid)"
        )
        return False
    report.notes.append(f"denylist={path} usable_patterns={usable}")
    return True


def load_exemptions(path: Path, report: Report) -> list[Exemption]:
    exemptions: list[Exemption] = []
    if not path.is_file():
        report.notes.append("exemptions_declared=0 (no exemptions file)")
        return exemptions
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if "::" not in entry:
            report.configuration_errors.append(f"exemption without a justification on line {number}")
            continue
        pattern_text, justification = (part.strip() for part in entry.split("::", 1))
        if not pattern_text or not justification:
            report.configuration_errors.append(f"exemption without a justification on line {number}")
            continue
        try:
            exemptions.append(Exemption(re.compile(pattern_text), justification))
        except re.error as error:
            report.configuration_errors.append(f"invalid exemption pattern on line {number}: {error}")
    report.notes.append(f"exemptions_declared={len(exemptions)} file={path.name}")
    return exemptions


def covered_spans(text: str, exemptions: list[Exemption]) -> tuple[list[tuple[int, int, str]], list[Exemption]]:
    spans: list[tuple[int, int, str]] = []
    used: list[Exemption] = []
    for exemption in exemptions:
        matched = False
        for match in exemption.pattern.finditer(text):
            spans.append((match.start(), match.end(), exemption.justification))
            matched = True
        if matched:
            used.append(exemption)
    return spans, used


def classify(
    text: str,
    patterns: list[re.Pattern],
    exemptions: list[Exemption],
    location: str,
    report: Report,
    identity: bool = False,
) -> None:
    spans, used = covered_spans(text, exemptions)
    for pattern in patterns:
        for match in pattern.finditer(text):
            start, end = match.span()
            covering = [why for span_start, span_end, why in spans if span_start <= start and end <= span_end]
            display = f"{location}: {match.group(0)[:DISPLAY_LIMIT]}"
            if covering:
                if identity:
                    report.known_identity.append(f"{display}   <= {covering[0]}")
                else:
                    report.exempted.append(f"{display}   <= {covering[0]}")
                continue
            partial = [why for span_start, span_end, why in spans if span_start < end and start < span_end]
            if partial:
                report.enforced.append(
                    f"{display}   [partially covered by a declared exemption, which may not hide part of a value]"
                )
            else:
                report.enforced.append(display)
    # An exemption that matched nothing here is simply unused; nothing to report.


def scan_tree(repo: Path, patterns: list[re.Pattern], exemptions: list[Exemption], report: Report) -> None:
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS)
        for name in sorted(files):
            path = Path(root) / name
            rel = path.relative_to(repo).as_posix()
            # Names are scanned too: an identifier hidden only in a file or
            # directory name is still an identifier in the repository.
            classify(rel, patterns, exemptions, f"HIT tree-path {rel}", report)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(content.splitlines(), start=1):
                classify(line, patterns, exemptions, f"HIT tree {rel}:{number}", report)


def scan_history(repo: Path, patterns: list[re.Pattern], exemptions: list[Exemption], report: Report) -> None:
    """History: paths, blob contents, commit messages and tag messages.

    Every reachable object is streamed through one `git cat-file --batch` pass and
    matched in Python. There is no `git grep -E` pre-filter, so a deny-list
    pattern that is valid for the matcher can never silently fail to match here.
    """
    order, paths = git_objects(repo)
    for sha in order:
        path = paths.get(sha, "")
        if path:
            classify(path, patterns, exemptions, f"HIT history-path {sha[:12]} {path}", report)
    for sha, kind, payload in batch_objects(repo, order):
        short = sha[:12]
        path = paths.get(sha, "")
        if kind == "blob":
            for number, line in enumerate(payload.decode("utf-8", "replace").splitlines(), start=1):
                classify(line, patterns, exemptions, f"HIT blob {short} {path}:{number}", report)
        elif kind == "commit":
            for line in object_message(payload).splitlines():
                classify(line, patterns, exemptions, f"HIT commit message {short}", report)
        elif kind == "tag":
            for line in object_message(payload).splitlines():
                classify(line, patterns, exemptions, f"HIT tag message {short}", report)


def scan_identity(
    repo: Path,
    patterns: list[re.Pattern],
    exemptions: list[Exemption],
    report: Report,
    authoritative: bool,
) -> None:
    expected_name = os.environ.get("EXPECTED_IDENTITY_NAME", "obsidian-gdrive-streaming")
    expected_email = os.environ.get("EXPECTED_IDENTITY_EMAIL", "").strip()
    allowed_email = re.compile(os.environ.get("ALLOWED_IDENTITY_EMAIL_RE", r"@users\.noreply\.github\.com$"))
    if authoritative and not expected_email:
        report.configuration_errors.append(
            "no EXPECTED_IDENTITY_EMAIL: an authoritative run must name the account the identity "
            "may belong to, because the address-shape allowlist alone does not enforce one"
        )

    names: set[str] = set()
    emails: set[str] = set()
    for line in run_git(repo, "log", "--all", "--format=%an%x00%cn%x00%ae%x00%ce").splitlines():
        parts = line.split("\x00")
        if len(parts) == 4:
            names.update({parts[0], parts[1]})
            emails.update({parts[2], parts[3]})
    for line in run_git(repo, "for-each-ref", "--format=%(taggername)%x00%(taggeremail)", "refs/tags").splitlines():
        parts = line.split("\x00")
        if len(parts) == 2:
            names.add(parts[0])
            emails.add(parts[1].strip("<>"))

    for name in sorted(filter(None, names)):
        if name != expected_name:
            report.enforced.append(f"HIT identity name: {name[:DISPLAY_LIMIT]} (expected {expected_name})")
        classify(name, patterns, exemptions, "HIT identity field", report, identity=True)
    for email in sorted(filter(None, emails)):
        if expected_email:
            if email.lower() != expected_email.lower():
                report.enforced.append(
                    f"HIT identity address: {email[:DISPLAY_LIMIT]} (not the declared distributing account)"
                )
        elif not allowed_email.search(email):
            report.enforced.append(f"HIT identity address: {email[:DISPLAY_LIMIT]} (outside the allowed pattern)")
        classify(email, patterns, exemptions, "HIT identity field", report, identity=True)
    report.notes.append(
        "identity_email_policy=" + ("exact:" + expected_email if expected_email else "address-shape allowlist (weaker)")
    )
    report.notes.append(f"distinct_identity_names={len(set(filter(None, names)))}")
    report.notes.append(f"distinct_identity_addresses={len(set(filter(None, emails)))}")


def scan_artefacts(repo: Path, patterns: list[re.Pattern], exemptions: list[Exemption], report: Report) -> None:
    for artefact in ARTEFACTS:
        path = repo / artefact
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(content.splitlines(), start=1):
            classify(line, patterns, exemptions, f"HIT artefact {artefact}:{number}", report)


def main() -> int:
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not (repo / ".git").exists():
        print(f"identity_scan=FAIL (not a git repository: {repo})")
        return 2

    report = Report()
    patterns = [re.compile(p) for p in BUILTIN_PATTERNS]
    authoritative = load_denylist(patterns, report)
    exemptions = load_exemptions(
        repo / os.environ.get("IDENTITY_EXEMPTIONS_REL_PATH", "scripts/identity-exemptions.txt"), report
    )
    strict = os.environ.get("IDENTITY_REQUIRE_NO_EXEMPTIONS", "0") == "1"

    print("== 0. configuration ==")
    print(f"builtin_patterns={len(BUILTIN_PATTERNS)}")
    for note in report.notes:
        print(note)
    print(f"excluded_dirs={','.join(sorted(EXCLUDED_DIRS))} (not distributed; a release is scanned under surface 5)")
    print(f"strict_mode={int(strict)}")

    if authoritative or os.environ.get("IDENTITY_ALLOW_NO_DENYLIST", "0") == "1":
        print("== 1. working tree (contents and names) ==")
        scan_tree(repo, patterns, exemptions, report)
        print("== 2. reachable history (blobs, paths, commit and tag messages) ==")
        scan_history(repo, patterns, exemptions, report)
        print("== 3. identity metadata (author, committer, tagger) ==")
        scan_identity(repo, patterns, exemptions, report, authoritative)
        print("== 4. release artefacts on disk ==")
        scan_artefacts(repo, patterns, exemptions, report)

    for line in report.enforced:
        print(line)
    for line in report.exempted:
        print(f"EXEMPT {line}")
    for line in report.known_identity:
        print(f"KNOWN-IDENTITY-EXCEPTION {line}")
    for line in report.configuration_errors:
        print(f"CONFIGURATION-ERROR {line}")

    counts = report.counts()
    print(" ".join(f"{key}={value}" for key, value in counts.items()))

    failed = True
    if not authoritative and os.environ.get("IDENTITY_ALLOW_NO_DENYLIST", "0") != "1":
        failed = True
    elif counts["enforced_hits"] > 0 or counts["configuration_errors"] > 0:
        failed = True
    else:
        failed = False

    if strict:
        reasons = []
        if counts["exempted_hits"] > 0:
            reasons.append(f"exemptions_used({counts['exempted_hits']})")
        if len(exemptions) > 0:
            reasons.append(f"exemptions_declared({len(exemptions)})")
        if counts["known_identity_exceptions"] > 0:
            reasons.append(f"known_identity_exceptions({counts['known_identity_exceptions']})")
        if reasons:
            failed = True
            print("strict_mode_failure=" + " ".join(reasons) + " — a repository that declares an exception cannot claim none")

    if failed:
        print("identity_scan=FAIL")
        # A configuration error is a different failure from a finding: the run
        # could not be authoritative, so it exits 2 rather than reporting a
        # finding-based failure.
        return 2 if counts["configuration_errors"] > 0 else 1
    if counts["exempted_hits"] > 0 or counts["known_identity_exceptions"] > 0 or len(exemptions) > 0:
        print("identity_scan=PASS_WITH_DECLARED_EXCEPTIONS")
    else:
        print("identity_scan=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
