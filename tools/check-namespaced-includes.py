#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT
"""Reject quicktrans-owned headers that can resolve to host LATX copies."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OWNED_HEADERS = {
    "fast-la-emit.h",
    "fast-template.h",
    "fast-translator.h",
    "fast_decoder.h",
    "latx-disassemble-trace.h",
    "x86.h",
}
INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')


def main():
    failures = []

    for path in sorted((ROOT / "src").rglob("*")):
        if path.suffix not in {".c", ".h"}:
            continue
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            match = INCLUDE.match(line)
            if match and match.group(1) in OWNED_HEADERS:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: "
                    f"use quicktrans/detail/{match.group(1)}"
                )

    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
