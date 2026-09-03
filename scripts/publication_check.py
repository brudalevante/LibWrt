#!/usr/bin/env python3
"""Reject files, metadata, and history that are unsafe for public release."""

from __future__ import annotations

import argparse
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 1_048_576

REQUIRED_PATHS = {
    ".gitattributes",
    ".gitignore",
    ".gitlab-ci.yml",
    "Justfile",
    "LICENSE",
    "README.md",
    "blog/index.html",
    "report/index.html",
    "patches/949-wifi-ath11k-use-private-page-frag-caches-for-rxdma.patch",
    "patches/950-wifi-ath11k-mark-private-rxfrag-validation-build.patch",
    "simulator/pagefrag_sim.py",
    "simulator/test_pagefrag_sim.py",
    "scripts/check_docs.py",
    "scripts/check_determinism.py",
    "scripts/e2e.sh",
    "scripts/publication_check.py",
    "scripts/test_publication_check.py",
}

ROOT_FILES = {
    ".gitattributes",
    ".gitignore",
    ".gitlab-ci.yml",
    "Justfile",
    "LICENSE",
    "README.md",
}

ALLOWED_SUFFIXES = {
    "blog": {".css", ".html", ".svg"},
    "report": {".css", ".html", ".svg"},
    "patches": {".patch"},
    "simulator": {".py"},
    "tools": {".awk", ".c", ".md"},
    "evidence": {".csv", ".md"},
    "mitigations": {".c", ".md"},
    "scripts": {".py", ".sh"},
}

ALLOWED_EXTENSIONLESS = {"mitigations/99-gro-fraglist-off"}

DENIED_SUFFIXES = {
    ".a", ".bin", ".bz2", ".cap", ".cmd", ".dump", ".elf", ".gz",
    ".ko", ".log", ".lz4", ".meta", ".mod", ".o", ".pcap", ".pcapng",
    ".so", ".tar", ".trace", ".xz", ".zip", ".zst",
}

DENIED_FILENAME_WORDS = re.compile(r"(?:^|[-_.])(capture|raw|trace)(?:[-_.]|$)", re.I)


@dataclass(frozen=True)
class ContentPattern:
    label: str
    regex: re.Pattern[str]


CONTENT_PATTERNS = (
    ContentPattern(
        "private IPv4 address",
        re.compile(
            r"(?<!\d)(?:"
            r"10(?:\.\d{1,3}){3}|"
            r"192\.168(?:\.\d{1,3}){2}|"
            r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|"
            r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}"
            r")(?!\d)"
        ),
    ),
    ContentPattern(
        "private IPv6 address",
        re.compile(r"(?i)(?<![0-9a-f])f[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){1,7}"),
    ),
    ContentPattern(
        "MAC address",
        re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])"),
    ),
    ContentPattern(
        "email address",
        re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
    ),
    ContentPattern(
        "absolute home-directory path",
        re.compile(r"(?i)(?:/(?:home|Users)/[a-z0-9._-]+|[a-z]:\\Users\\[^\\\s]+)"),
    ),
    ContentPattern(
        "private key material",
        re.compile(r"(?i)-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    ),
    ContentPattern(
        "SSH public key",
        re.compile(r"(?m)^\s*(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/]{40,}"),
    ),
    ContentPattern(
        "SSH fingerprint",
        re.compile(r"\bSHA256:[A-Za-z0-9+/]{20,}={0,2}\b"),
    ),
    ContentPattern(
        "authorization header",
        re.compile(r"(?i)\bAuthorization\s*:\s*(?:Basic|Bearer)\s+\S+"),
    ),
    ContentPattern(
        "secret-like assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
            r"private[_-]?key|preshared[_-]?key|psk|secret)\s*[:=]\s*['\"]?\S+"
        ),
    ),
    ContentPattern(
        "known token format",
        re.compile(
            r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
            r"glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|"
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
        ),
    ),
    ContentPattern(
        "UUID",
        re.compile(
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
        ),
    ),
    ContentPattern(
        "private hostname",
        re.compile(r"(?i)\b[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.(?:corp|internal|lan|local)\b"),
    ),
    ContentPattern(
        "SSH-style remote",
        re.compile(r"(?i)\b[a-z0-9._-]+@[a-z0-9.-]+:[a-z0-9_./-]+"),
    ),
    ContentPattern("root SSH target", re.compile(r"(?i)\broot@[a-z0-9_.:-]+")),
    ContentPattern(
        "wireless identifier assignment",
        re.compile(r"(?i)\b(?:bssid|ssid)\s*[:=]\s*['\"]?[^\s'\"<]+"),
    ),
    ContentPattern(
        "private-repository reference",
        re.compile(
            r"(?i)(?:(?:^|[\"'(= ])(?:backlog|cruft|reports)/|"
            r"driver-analysis/" r"debug-kernel/|prompt_for_" r"codex|live-" r"status-[0-9])"
        ),
    ),
)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("git", "-C", str(ROOT), *args),
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def path_allowed(path: str) -> bool:
    posix = PurePosixPath(path)
    if path in ROOT_FILES or path in ALLOWED_EXTENSIONLESS:
        return True
    if len(posix.parts) < 2:
        return False
    suffixes = ALLOWED_SUFFIXES.get(posix.parts[0])
    return suffixes is not None and posix.suffix.lower() in suffixes


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_text(path: str, text: str) -> list[str]:
    violations: list[str] = []
    for pattern in CONTENT_PATTERNS:
        for match in pattern.regex.finditer(text):
            violations.append(
                f"{path}:{line_number(text, match.start())}: {pattern.label}"
            )
    return violations


def inspect_blob(path: str, data: bytes, *, enforce_path: bool = True) -> list[str]:
    violations: list[str] = []
    suffix = PurePosixPath(path.lower()).suffix

    if enforce_path and not path_allowed(path):
        violations.append(f"{path}: path is outside the public allowlist")
    if suffix in DENIED_SUFFIXES:
        violations.append(f"{path}: forbidden artifact extension")
    if DENIED_FILENAME_WORDS.search(PurePosixPath(path).name):
        violations.append(f"{path}: filename identifies raw capture/trace material")
    if len(data) > MAX_FILE_BYTES:
        violations.append(f"{path}: file exceeds {MAX_FILE_BYTES} bytes")
    if b"\0" in data:
        violations.append(f"{path}: binary NUL byte")
        return violations
    if b"\r\n" in data:
        violations.append(f"{path}: CRLF line endings")
    if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
        violations.append(f"{path}: Git LFS pointer")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        violations.append(f"{path}: invalid UTF-8")
        return violations

    violations.extend(scan_text(path, text))
    return violations


def worktree_paths() -> list[str]:
    result = git("ls-files", "-co", "--exclude-standard", "-z")
    return sorted(
        item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item
    )


def scan_worktree() -> list[str]:
    violations: list[str] = []
    paths = worktree_paths()
    missing = sorted(REQUIRED_PATHS.difference(paths))
    violations.extend(f"{path}: required publication file is missing" for path in missing)

    for path in paths:
        absolute = ROOT / path
        mode = absolute.lstat().st_mode
        if stat.S_ISLNK(mode):
            violations.append(f"{path}: symlink is not allowed")
            continue
        if not stat.S_ISREG(mode):
            violations.append(f"{path}: non-regular file is not allowed")
            continue
        violations.extend(inspect_blob(path, absolute.read_bytes()))
    return violations


def has_head() -> bool:
    return git("rev-parse", "--verify", "HEAD", check=False).returncode == 0


def scan_commit_metadata() -> list[str]:
    violations: list[str] = []
    fmt = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"
    raw = git("log", "--all", f"--format={fmt}").stdout.decode("utf-8", "strict")
    safe_name = re.compile(r"^[A-Za-z0-9_.-]+$")
    safe_email = re.compile(r"(?i)noreply|no-reply")

    for record in raw.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        fields = record.split("\x1f", 5)
        if len(fields) != 6:
            violations.append("history: malformed commit metadata")
            continue
        commit, author_name, author_email, committer_name, committer_email, message = fields
        short = commit[:12]
        if not safe_name.fullmatch(author_name):
            violations.append(f"commit {short}: author name is not a public pseudonym")
        if not safe_name.fullmatch(committer_name):
            violations.append(f"commit {short}: committer name is not a public pseudonym")
        if not safe_email.search(author_email):
            violations.append(f"commit {short}: author email is not a no-reply address")
        if not safe_email.search(committer_email):
            violations.append(f"commit {short}: committer email is not a no-reply address")
        violations.extend(scan_text(f"commit {short} message", message))
    return violations


def scan_history_blobs() -> list[str]:
    violations: list[str] = []
    seen: set[str] = set()
    lines = git("rev-list", "--objects", "--all").stdout.decode("utf-8").splitlines()
    for line in lines:
        object_id, _, path = line.partition(" ")
        if object_id in seen:
            continue
        if git("cat-file", "-t", object_id).stdout.strip() != b"blob":
            continue
        seen.add(object_id)
        display_path = path or f"history-object-{object_id[:12]}"
        data = git("cat-file", "-p", object_id).stdout
        violations.extend(inspect_blob(display_path, data, enforce_path=bool(path)))
    return violations


def scan_history(*, bootstrap: bool) -> list[str]:
    if not has_head():
        return []

    violations: list[str] = []
    roots = git("rev-list", "--all", "--max-parents=0").stdout.splitlines()
    if len(roots) != 1:
        violations.append("history: expected exactly one root commit")

    git_dir = Path(git("rev-parse", "--git-dir").stdout.decode().strip())
    if not git_dir.is_absolute():
        git_dir = ROOT / git_dir
    if (git_dir / "shallow").exists():
        violations.append("history: shallow repository cannot prove complete ancestry")
    if (git_dir / "objects/info/alternates").exists():
        violations.append("history: object alternates are not allowed")
    if git("for-each-ref", "--format=%(refname)", "refs/replace").stdout:
        violations.append("history: replacement refs are not allowed")

    if bootstrap:
        if git("for-each-ref", "--format=%(refname)", "refs/tags").stdout:
            violations.append("history: tags are not allowed during public bootstrap")
        heads = {
            item.decode("utf-8")
            for item in git(
                "for-each-ref", "--format=%(refname)", "refs/heads"
            ).stdout.splitlines()
        }
        if heads.difference({"refs/heads/main"}):
            violations.append("history: bootstrap permits only refs/heads/main")

    violations.extend(scan_commit_metadata())
    violations.extend(scan_history_blobs())
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="also require a clean main ref with no tags",
    )
    args = parser.parse_args()

    try:
        violations = scan_worktree()
        violations.extend(scan_history(bootstrap=args.bootstrap))
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        print(f"publication check internal error: {type(error).__name__}", file=sys.stderr)
        return 2

    unique = sorted(set(violations))
    if unique:
        for violation in unique:
            print(f"FAIL: {violation}")
        print(f"publication check failed with {len(unique)} violation(s)")
        return 1

    scope = "worktree and reachable history" if has_head() else "worktree"
    print(f"publication check passed: {scope}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
