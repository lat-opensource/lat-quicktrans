#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import re
import sys
from pathlib import Path


def parse_descriptors(path):
    text = Path(path).read_text()
    pattern = re.compile(
        r"^\s*\[(FT_[A-Z0-9_]+)\]\s*=\s*\{(.*?)(?=\n\s*\[FT_|\n\};)",
        re.MULTILINE | re.DOTALL,
    )
    descriptors = {}
    errors = []

    for match in pattern.finditer(text):
        kind = match.group(1)
        body = match.group(2)
        if kind in descriptors:
            errors.append(f"{kind}: duplicate descriptor")
        descriptors[kind] = {
            "has_metadata": (
                "FT_TM_CONSTRAINTS_DECLARED" in body
                or "FT_TM_NO_EXTRA_CONSTRAINTS" in body
            ),
        }

    return descriptors, errors


def parse_constraint_cases(paths):
    text = "\n".join(Path(path).read_text() for path in paths)
    match = re.search(
        r"^static bool fast_template_emit_constraints_ok\([^)]*\)\n\{",
        text,
        re.MULTILINE,
    )
    if not match:
        raise RuntimeError("fast_template_emit_constraints_ok() not found")
    depth = 0
    end = match.end() - 1
    for pos in range(end, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                end = pos + 1
                break
    else:
        raise RuntimeError("fast_template_emit_constraints_ok() is incomplete")
    body = text[match.start():end]
    return set(re.findall(r"\bcase\s+(FT_[A-Z0-9_]+)\s*:", body))


def main(argv):
    if len(argv) < 3:
        print(
            "usage: check-fast-template-constraints.py "
            "<fast_decoder_template.c> <constraint-source>...",
            file=sys.stderr,
        )
        return 2

    descriptors, errors = parse_descriptors(argv[1])
    constraint_cases = parse_constraint_cases(argv[2:])

    for kind, desc in sorted(descriptors.items()):
        if desc["has_metadata"] or kind in constraint_cases:
            continue
        errors.append(
            f"{kind}: missing constraint metadata "
            "or explicit fast_template_emit_constraints_ok() case"
        )

    if errors:
        print("fast template constraint check failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
