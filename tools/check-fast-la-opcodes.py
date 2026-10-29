#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import re
import sys
from pathlib import Path


def parse_fast_macros(path):
    text = Path(path).read_text()
    macros = {}
    errors = []

    pattern = re.compile(
        r"^#define\s+LA_([A-Z0-9_]+)\s+0x([0-9a-fA-F]+)u?\b",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        name = match.group(1)
        value = int(match.group(2), 16)
        if name in macros and macros[name] != value:
            errors.append(
                f"LA_{name}: duplicate macro values "
                f"0x{macros[name]:08x} and 0x{value:08x}"
            )
        macros[name] = value

    return macros, errors


def parse_fast_generated_opcodes(path):
    text = Path(path).read_text()
    pattern = re.compile(
        r"\bFT_LA_OPCODE_([A-Z0-9_]+)\s*=\s*"
        r"(0x[0-9a-fA-F]+|0)\s*,"
    )
    return {
        match.group(1): int(match.group(2), 0)
        for match in pattern.finditer(text)
    }


def parse_fast_opcode_uses(path):
    text = Path(path).read_text()
    return set(re.findall(r"\bFT_LA_OPCODE_([A-Z0-9_]+)\b", text))


def parse_format_table(path):
    text = Path(path).read_text()
    pattern = re.compile(
        r"\{LISA_([A-Z0-9_]+),\s*0x([0-9a-fA-F]+),"
    )
    return {
        match.group(1): int(match.group(2), 16)
        for match in pattern.finditer(text)
    }


def main(argv):
    if len(argv) < 4:
        print(
            "usage: check-fast-la-opcodes.py "
            "<fast-translator-source>... <fast-la-emit.h> <format-table.h>",
            file=sys.stderr,
        )
        return 2

    source_paths = argv[1:-2]
    generated = parse_fast_generated_opcodes(argv[-2])
    formats = parse_format_table(argv[-1])
    errors = []

    for source_path in source_paths:
        macros, macro_errors = parse_fast_macros(source_path)
        errors.extend(macro_errors)

        if macros:
            for name in sorted(macros):
                errors.append(
                    f"{source_path}: LA_{name}: "
                    "hand-written fast translator opcode"
                )

        for name in sorted(parse_fast_opcode_uses(source_path)):
            if name not in generated:
                errors.append(
                    f"{source_path}: FT_LA_OPCODE_{name}: "
                    "missing generated opcode"
                )

    for name, value in sorted(generated.items()):
        expected = formats.get(name)
        if expected is None:
            continue
        if value != expected:
            errors.append(
                f"FT_LA_OPCODE_{name}: fast-la-emit=0x{value:08x} "
                f"format-table=0x{expected:08x}"
            )

    if errors:
        print("fast translator LA opcode check failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
