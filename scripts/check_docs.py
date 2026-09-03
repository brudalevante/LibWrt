#!/usr/bin/env python3
"""Validate standalone HTML/SVG documentation and normalized evidence."""

from __future__ import annotations

import csv
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CYCLE_HEADER = (
    "cycle", "sequence", "elapsed_seconds", "uptime_seconds",
    "mem_available_kb", "pagefrag_allocinfo_bytes", "records",
    "scoped_records", "allocations", "scoped_allocations",
    "unscoped_allocations", "head_fragment_releases", "tracked_pages",
    "tracked_backing_bytes", "tracked_aligned_bytes", "tracked_slack_bytes",
    "single_ring_pages", "cross_ring_pages", "ring_unscoped_pages",
    "unscoped_only_pages", "history_cross_lifetime_pages",
    "history_same_ring_pages", "unscoped_current",
    "global_idr_remove_unmatched", "ring_count", "actual_idr_total",
    "ring_allocations", "ring_posts", "ring_reaps",
    "ring_fragment_releases", "ring_untracked_removes", "allocated_current",
    "posted_current", "reaped_current",
    "posted_unique_pages_sum_not_physical",
    "posted_backing_sum_not_physical", "critical_failures", "nmissed_total",
    "scope_context_mismatches",
)

RING_HEADER = (
    "cycle", "kind", "radio_index", "actual_idr", "tracked_posted",
    "allocations", "reaps", "releases", "posted_unique_pages",
    "posted_aligned_bytes", "posted_backing_bytes",
)


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.duplicate_ids: set[str] = set()
        self.references: list[tuple[str, str]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        for name, value in attrs:
            if value is None:
                continue
            if name == "id":
                if value in self.ids:
                    self.duplicate_ids.add(value)
                self.ids.add(value)
            if name in {"href", "src"}:
                self.references.append((name, value))

    handle_startendtag = handle_starttag


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def check_html() -> list[str]:
    errors: list[str] = []
    parsed: dict[Path, DocumentParser] = {}

    for path in sorted(ROOT.glob("**/*.html")):
        parser = DocumentParser()
        try:
            parser.feed(path.read_text(encoding="utf-8"))
            parser.close()
        except Exception as error:
            errors.append(f"{relative(path)}: HTML parse error: {type(error).__name__}")
            continue
        parsed[path.resolve()] = parser
        for duplicate in sorted(parser.duplicate_ids):
            errors.append(f"{relative(path)}: duplicate HTML id {duplicate}")

    for source, parser in parsed.items():
        for attribute, reference in parser.references:
            split = urllib.parse.urlsplit(reference)
            if split.scheme or split.netloc:
                if split.scheme not in {"http", "https"}:
                    errors.append(
                        f"{relative(source)}: unsafe {attribute} scheme in local documentation"
                    )
                continue

            decoded_path = urllib.parse.unquote(split.path)
            target = source if not decoded_path else (source.parent / decoded_path).resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                errors.append(f"{relative(source)}: link escapes repository root")
                continue
            if not target.is_file():
                errors.append(f"{relative(source)}: missing local target {decoded_path}")
                continue
            if split.fragment:
                target_parser = parsed.get(target)
                if target_parser is None:
                    errors.append(f"{relative(source)}: fragment points to non-HTML target")
                elif urllib.parse.unquote(split.fragment) not in target_parser.ids:
                    errors.append(f"{relative(source)}: missing fragment {split.fragment}")
    return errors


def local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def check_svg() -> list[str]:
    errors: list[str] = []
    url_reference = re.compile(r"url\(#([^)]+)\)")

    for path in sorted(ROOT.glob("**/*.svg")):
        raw = path.read_bytes()
        upper = raw.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            errors.append(f"{relative(path)}: SVG contains a declaration/entity")
            continue
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            errors.append(f"{relative(path)}: invalid SVG XML")
            continue
        if local_name(root.tag) != "svg":
            errors.append(f"{relative(path)}: XML root is not svg")
            continue

        ids: set[str] = set()
        references: list[str] = []
        for element in root.iter():
            name = local_name(element.tag)
            if name in {"script", "foreignObject"}:
                errors.append(f"{relative(path)}: forbidden SVG element {name}")
            element_id = element.attrib.get("id")
            if element_id:
                if element_id in ids:
                    errors.append(f"{relative(path)}: duplicate SVG id {element_id}")
                ids.add(element_id)
            for attribute, value in element.attrib.items():
                attribute_name = local_name(attribute)
                if attribute_name.lower().startswith("on"):
                    errors.append(f"{relative(path)}: SVG event-handler attribute")
                if attribute_name == "href" and value and not value.startswith("#"):
                    errors.append(f"{relative(path)}: external SVG href")
                references.extend(url_reference.findall(value))
        for target in references:
            if target not in ids:
                errors.append(f"{relative(path)}: unresolved SVG reference {target}")
    return errors


def read_csv(path: Path, expected: tuple[str, ...]) -> tuple[list[list[str]], list[str]]:
    errors: list[str] = []
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    if not rows:
        return [], [f"{relative(path)}: empty CSV"]
    if tuple(rows[0]) != expected:
        errors.append(f"{relative(path)}: unexpected CSV header")
    for line, row in enumerate(rows[1:], start=2):
        if len(row) != len(expected):
            errors.append(f"{relative(path)}:{line}: non-rectangular CSV row")
    return rows[1:], errors


def check_evidence() -> list[str]:
    errors: list[str] = []
    cycle_path = ROOT / "evidence/rxown-cycles.csv"
    ring_path = ROOT / "evidence/rxown-rings-final.csv"
    cycle_rows, cycle_errors = read_csv(cycle_path, CYCLE_HEADER)
    ring_rows, ring_errors = read_csv(ring_path, RING_HEADER)
    errors.extend(cycle_errors)
    errors.extend(ring_errors)

    elapsed_by_cycle: dict[str, list[int]] = defaultdict(list)
    for line, row in enumerate(cycle_rows, start=2):
        if len(row) != len(CYCLE_HEADER):
            continue
        if not re.fullmatch(r"cycle[0-9]+", row[0]):
            errors.append(f"{relative(cycle_path)}:{line}: invalid symbolic cycle")
        try:
            sequence = int(row[1])
            elapsed = int(row[2])
            tuple(int(value) for value in row[3:])
        except ValueError:
            errors.append(f"{relative(cycle_path)}:{line}: non-integer evidence value")
            continue
        if sequence <= 0 or elapsed < 0:
            errors.append(f"{relative(cycle_path)}:{line}: invalid sequence/time")
        elapsed_by_cycle[row[0]].append(elapsed)

    for cycle, elapsed in elapsed_by_cycle.items():
        if not elapsed or elapsed[0] != 0 or elapsed != sorted(elapsed):
            errors.append(f"{relative(cycle_path)}: non-normalized time for {cycle}")

    for line, row in enumerate(ring_rows, start=2):
        if len(row) != len(RING_HEADER):
            continue
        if not re.fullmatch(r"cycle[0-9]+", row[0]):
            errors.append(f"{relative(ring_path)}:{line}: invalid symbolic cycle")
        try:
            tuple(int(value) for value in row[1:])
        except ValueError:
            errors.append(f"{relative(ring_path)}:{line}: non-integer evidence value")
    return errors


def main() -> int:
    errors = check_html() + check_svg() + check_evidence()
    if errors:
        for error in sorted(set(errors)):
            print(f"FAIL: {error}")
        return 1
    print("documentation and normalized evidence checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
