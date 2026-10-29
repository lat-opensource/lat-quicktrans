#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import re
import sys


TABLE_ENTRY_RE = re.compile(r"\[(FT_[A-Z0-9_]+)\]\s*=")
SWITCH_CASE_RE = re.compile(r"case\s+(FT_[A-Z0-9_]+)\s*:")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} DISPATCH_SOURCE TEMPLATE_SOURCE",
              file=sys.stderr)
        return 2

    dispatch = pathlib.Path(sys.argv[1]).read_text()
    template = pathlib.Path(sys.argv[2]).read_text()
    table_entries = set(TABLE_ENTRY_RE.findall(dispatch))
    switch_cases = set(SWITCH_CASE_RE.findall(template))

    if not table_entries or not switch_cases:
        print("failed to parse emitter dispatch inputs", file=sys.stderr)
        return 1

    overlap = sorted(table_entries & switch_cases)
    if overlap:
        print("emitter kinds duplicated by function table and switch: " +
              ", ".join(overlap), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
