#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from fast_la_reference import parse_bit_fields


def c_name(name):
    return name.replace(".", "_").upper()


def sample_value(opnd, ranges, index):
    bits = sum(end - start + 1 for start, end in ranges)
    if opnd.startswith("imm_si") or opnd.startswith("imm_off"):
        return -((index % 5) + 1)
    mask = (1 << bits) - 1
    value = ((index + 1) * 3) & mask
    return value if value else 1


def encode(opcode, opnds, values, fields):
    insn = int(opcode, 0)
    for opnd, value in zip(opnds, values):
        if opnd == "opd_invalid":
            continue
        consumed = 0
        for start, end in fields[opnd]:
            bits = end - start + 1
            mask = (1 << bits) - 1
            insn |= ((value >> consumed) & mask) << start
            consumed += bits
    return insn & 0xffffffff


def build_test_source(insts, fields):
    lines = [
        "#include <stdint.h>",
        "#include <stdio.h>",
        '#include "fast-la-emit.h"',
        "",
        "int main(void)",
        "{",
    ]
    for idx, (name, desc) in enumerate(insts.items()):
        if name in ("invalid", "ending", "nop"):
            continue
        if int(desc["opcode"], 0) <= 0:
            continue
        opnds = [opnd for opnd in desc["opnd"] if opnd != "opd_invalid"]
        if any(opnd not in fields for opnd in opnds):
            continue
        values = [
            sample_value(opnd, fields[opnd], idx + op_idx)
            for op_idx, opnd in enumerate(opnds)
        ]
        expected = encode(desc["opcode"], opnds, values, fields)
        args = ", ".join(str(value) for value in values)
        func = "FT_LA_" + c_name(name)
        lines.append(
            "    if ({}({}) != UINT32_C(0x{:08x})) {{".format(
                func, args, expected
            )
        )
        lines.append(
            '        printf("{} mismatch: 0x%08x != 0x{:08x}\\n", {}({}));'.format(
                func, expected, func, args
            )
        )
        lines.append("        return 1;")
        lines.append("    }")
    lines.append("    if (FT_LA_NOP() != UINT32_C(0x03400000)) {")
    lines.append('        printf("FT_LA_NOP mismatch: 0x%08x != 0x03400000\\n", FT_LA_NOP());')
    lines.append("        return 1;")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 4:
        print(
            "usage: check-fast-la-emit.py "
            "<inst_template.json> <ir2-assemble.c> <include-dir>",
            file=sys.stderr,
        )
        return 2

    cc = shutil.which("cc")
    if cc is None:
        print("cc not found", file=sys.stderr)
        return 1

    insts = json.loads(Path(argv[1]).read_text())
    fields = parse_bit_fields(argv[2])
    include_dir = Path(argv[3])

    with tempfile.TemporaryDirectory(prefix="fast-la-emit-") as tmp:
        tmp = Path(tmp)
        source = tmp / "check-fast-la-emit.c"
        binary = tmp / "check-fast-la-emit"
        source.write_text(build_test_source(insts, fields))
        subprocess.run(
            [cc, "-std=c11", "-I", str(include_dir), str(source), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
