#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path("/development/ordl-infra")
OUTPUT_DIR = REPO_ROOT / "analysis" / "handala-stryker-intel"
SEARCH_PATTERN = re.compile(r"handala|stryker", re.IGNORECASE)
SEARCH_QUERY = "Handala OR Stryker"


def git_output(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), *args],
        text=True,
    ).strip()


def iter_tracked_files() -> list[Path]:
    raw = subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
    )
    return [REPO_ROOT / path for path in raw.decode("utf-8").split("\0") if path]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_newlines(text: str) -> list[str]:
    return text.splitlines()


def matched_terms(text: str) -> list[str]:
    found = {match.group(0).lower() for match in SEARCH_PATTERN.finditer(text)}
    return sorted(found)


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def main() -> None:
    ensure_clean_dir(OUTPUT_DIR)
    source_dir = OUTPUT_DIR / "source"
    source_dir.mkdir(parents=True, exist_ok=True)

    commit = git_output("rev-parse", "HEAD")
    branch = git_output("rev-parse", "--abbrev-ref", "HEAD")

    file_records: list[dict] = []
    line_rows: list[dict] = []
    search_result_lines: list[str] = []
    full_corpus_parts: list[str] = []

    tracked_files = iter_tracked_files()
    matched_files = []
    total_match_lines = 0
    total_term_occurrences = 0

    for abs_path in tracked_files:
        rel_path = abs_path.relative_to(REPO_ROOT)
        try:
            raw = abs_path.read_bytes()
            text = raw.decode("utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        if not SEARCH_PATTERN.search(text):
            continue

        matched_files.append(abs_path)
        out_path = source_dir / rel_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)

        lines = normalize_newlines(text)
        match_rows = []
        terms_present = matched_terms(text)
        term_occurrences = len(list(SEARCH_PATTERN.finditer(text)))
        total_term_occurrences += term_occurrences

        for idx, line in enumerate(lines, start=1):
            line_terms = matched_terms(line)
            if not line_terms:
                continue

            total_match_lines += 1
            row = {
                "document_id": str(rel_path),
                "relative_path": str(rel_path),
                "line_number": idx,
                "matched_terms": "|".join(line_terms),
                "line_text": line,
            }
            line_rows.append(row)
            match_rows.append(
                {
                    "line_number": idx,
                    "matched_terms": line_terms,
                    "line_text": line,
                }
            )
            search_result_lines.append(f"{rel_path}:{idx}:{line}")

        record = {
            "document_id": str(rel_path),
            "repo_name": "Open-Research-Development-Laboratories/ordl-infra",
            "repo_root": str(REPO_ROOT),
            "relative_path": str(rel_path),
            "absolute_path": str(abs_path),
            "commit": commit,
            "branch": branch,
            "search_query": SEARCH_QUERY,
            "search_pattern": SEARCH_PATTERN.pattern,
            "size_bytes": len(raw),
            "sha256": sha256_bytes(raw),
            "line_count": len(lines),
            "terms_present": terms_present,
            "term_occurrences": term_occurrences,
            "match_line_count": len(match_rows),
            "matched_lines": match_rows,
            "text": text,
            "content_base64": base64.b64encode(raw).decode("ascii"),
        }
        file_records.append(record)

        full_corpus_parts.append(
            "\n".join(
                [
                    f"===== BEGIN FILE: {rel_path} =====",
                    text,
                    f"===== END FILE: {rel_path} =====",
                    "",
                ]
            )
        )

    file_records.sort(key=lambda item: item["relative_path"])
    line_rows.sort(key=lambda item: (item["relative_path"], item["line_number"]))
    search_result_lines.sort()

    manifest = {
        "generated_at": subprocess.check_output(
            ["date", "--iso-8601=seconds"],
            text=True,
        ).strip(),
        "repo_name": "Open-Research-Development-Laboratories/ordl-infra",
        "repo_root": str(REPO_ROOT),
        "commit": commit,
        "branch": branch,
        "search_query": SEARCH_QUERY,
        "search_pattern": SEARCH_PATTERN.pattern,
        "matched_file_count": len(file_records),
        "matched_line_count": total_match_lines,
        "term_occurrence_count": total_term_occurrences,
        "files": [
            {
                "document_id": record["document_id"],
                "relative_path": record["relative_path"],
                "absolute_path": record["absolute_path"],
                "size_bytes": record["size_bytes"],
                "sha256": record["sha256"],
                "line_count": record["line_count"],
                "terms_present": record["terms_present"],
                "term_occurrences": record["term_occurrences"],
                "match_line_count": record["match_line_count"],
            }
            for record in file_records
        ],
    }

    (OUTPUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    with (OUTPUT_DIR / "documents.jsonl").open("w", encoding="utf-8") as handle:
        for record in file_records:
            handle.write(json.dumps(record, ensure_ascii=False) + os.linesep)

    with (OUTPUT_DIR / "match_lines.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["document_id", "relative_path", "line_number", "matched_terms", "line_text"],
        )
        writer.writeheader()
        writer.writerows(line_rows)

    (OUTPUT_DIR / "search_results.txt").write_text(
        "\n".join(search_result_lines) + ("\n" if search_result_lines else ""),
        encoding="utf-8",
    )

    (OUTPUT_DIR / "full_corpus.txt").write_text(
        "\n".join(full_corpus_parts),
        encoding="utf-8",
    )

    readme = [
        "# Handala/Stryker Search Dataset",
        "",
        "This folder contains the exact repository files that matched the search query `Handala OR Stryker`,",
        "plus normalized artifacts for AI ingestion and analyst review.",
        "",
        "## Files",
        "",
        "- `manifest.json`: corpus inventory, counts, hashes, and search provenance.",
        "- `documents.jsonl`: one JSON document per matched file with metadata, hit lines, full text, and Base64 content.",
        "- `match_lines.csv`: line-level hits for quick filtering.",
        "- `search_results.txt`: grep-style hit list derived from the current commit.",
        "- `full_corpus.txt`: concatenated full text for every matched file.",
        "- `source/`: exact byte-for-byte copies of every matched file, preserving relative paths.",
        "- `REPORT.md`: human-readable operational analysis.",
        "",
        f"Matched files: {len(file_records)}",
        f"Matched lines: {total_match_lines}",
        f"Term occurrences: {total_term_occurrences}",
        f"Commit: {commit}",
        "",
    ]
    (OUTPUT_DIR / "README.md").write_text("\n".join(readme), encoding="utf-8")


if __name__ == "__main__":
    main()
