#!/usr/bin/env python3
"""Compare two sorry manifests (base vs head) and report newly introduced
sorry-tainted declarations in hand-written specs as a PR comment.

Usage:
    python3 scripts/sorry-diff.py <base-manifest> <head-manifest>

Environment variables (set by CI):
    GITHUB_STEP_SUMMARY  - path to the job summary file
    GITHUB_OUTPUT        - path to set workflow step outputs
    SORRY_FAIL_ON_NEW    - if "true", exit 1 when new specs sorries are found

Outputs:
    .sorry-delta-comment.md  - written only when new specs sorries exist
    step output post_comment - "true" when the comment file is written
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

COMMENT_FILE = ".sorry-delta-comment.md"
SPECS_MODULE_PREFIX = "Spqr.Specs"
MAX_ROWS = 50


def read_manifest(path: Path) -> dict[str, str]:
    """Parse manifest into {decl: full_line} keyed by declaration name.

    Lean declaration names are globally unique, so the declaration column
    alone is sufficient as an identity key.  The full line (including module
    and kind) is kept for display purposes.
    """
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            result[parts[1]] = line
    return result


def parse_line(line: str) -> tuple[str, str, str]:
    parts = line.split()
    return (parts[0] if len(parts) > 0 else "",
            parts[1] if len(parts) > 1 else "",
            parts[2] if len(parts) > 2 else "")


def is_specs_line(line: str) -> bool:
    """Match modules that Audit.lean considers specs: name == or starts with Spqr.Specs."""
    mod = line.split()[0] if line.split() else ""
    return mod == SPECS_MODULE_PREFIX or mod.startswith(SPECS_MODULE_PREFIX + ".")


def build_body(new_specs_lines: list[str]) -> str:
    count = len(new_specs_lines)
    s = "s" if count > 1 else ""

    lines = [
        "### Sorry Delta — hand-written specs",
        "",
        f"**{count} new sorry-tainted declaration{s} in `Spqr.Specs.*`:**",
        "",
        "| Module | Declaration | Kind |",
        "|--------|-------------|------|",
    ]

    for entry in new_specs_lines[:MAX_ROWS]:
        mod, decl, kind = parse_line(entry)
        lines.append(f"| `{mod}` | `{decl}` | {kind} |")

    remaining = count - MAX_ROWS
    if remaining > 0:
        lines.append("")
        lines.append(f"... and {remaining} more (see full manifest in job log)")

    return "\n".join(lines)


def set_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT", "")
    if output_path:
        with open(output_path, "a") as f:
            f.write(f"{name}={value}\n")


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: sorry-diff.py <base-manifest> <head-manifest>", file=sys.stderr)
        sys.exit(1)

    base_path = Path(sys.argv[1])
    head_path = Path(sys.argv[2])

    if not head_path.exists():
        print(f"Error: head manifest not found at '{head_path}'", file=sys.stderr)
        sys.exit(1)

    head_decls = read_manifest(head_path)
    total = len(head_decls)

    has_baseline = base_path.exists()
    if has_baseline:
        base_decls = read_manifest(base_path)
        new_keys = sorted(set(head_decls) - set(base_decls))
        new_lines = [head_decls[k] for k in new_keys]
    else:
        new_lines = []

    new_specs_lines = [l for l in new_lines if is_specs_line(l)]

    print("--- Sorry Delta Summary ---")
    print(f"Total sorry-tainted: {total}")
    if has_baseline:
        print(f"New in this PR (all): {len(new_lines)}")
        print(f"New in this PR (specs): {len(new_specs_lines)}")
    else:
        print("No baseline available for comparison.")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"Sorry-tainted total: {total}\n")
            if has_baseline:
                f.write(f"New (all): {len(new_lines)}, New (specs): {len(new_specs_lines)}\n")

    if new_specs_lines:
        body = build_body(new_specs_lines)
        Path(COMMENT_FILE).write_text(body + "\n")
        set_output("post_comment", "true")
        for entry in new_specs_lines:
            mod, decl, kind = parse_line(entry)
            print(f"  ⚠  [{mod}] {decl} ({kind})")
    else:
        set_output("post_comment", "false")
        if has_baseline:
            print("✓  No new sorry-tainted declarations in hand-written specs.")

    if os.environ.get("SORRY_FAIL_ON_NEW") == "true" and new_specs_lines:
        print(f"::error::{len(new_specs_lines)} new sorry-tainted declaration(s) in specs")
        sys.exit(1)


if __name__ == "__main__":
    main()
