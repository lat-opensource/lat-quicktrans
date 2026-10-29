#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import re
import sys


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    cache = pathlib.Path(sys.argv[1]).read_text()
    emitter = pathlib.Path(sys.argv[2]).read_text()

    if "static __thread FtInstPatternTable" not in cache:
        return fail("instruction pattern cache must be thread-local")
    if not re.search(
        r"FT_INST_PATTERN_TABLE_SIZE\s+\(1u\s*<<\s*"
        r"FT_INST_PATTERN_TABLE_BITS\)", cache,
    ):
        return fail("instruction pattern cache must have a fixed table size")
    if "fields->alu_op == FT_ALU_NONE" not in cache:
        return fail("instruction pattern cache must only accept ALU templates")
    if "fields->segment >= 0" not in cache:
        return fail("segmented templates must bypass the pattern cache")
    if not re.search(
        r"fields->alu_form != FT_ALU_FORM_ACC_IMM\s*&&\s*"
        r"fields->modrm_mod != 3", cache,
    ):
        return fail("memory ALU templates must bypass the pattern cache")
    if any(token in cache for token in
           ("fields->address", "calloc(", "malloc(", "realloc(")):
        return fail("pattern keys must not depend on addresses or allocation")
    if "ft_inst_pattern_table.keys[index] == key" not in cache:
        return fail("pattern hits must compare the complete compact key")
    if cache.count("emit_template_fields_uncached(") != 2:
        return fail("bypass and miss paths must use the existing emitter")
    if "static int emit_template_fields_uncached(" not in emitter:
        return fail("the existing emitter must remain the semantic source")
    if "for (unsigned probe" in cache:
        return fail("pattern lookup must not use a probe chain")
    if "memcpy(" in cache:
        return fail("small pattern copies must not call memcpy")
    if "#ifdef QUICKTRANS_INST_PATTERN_STATS" not in cache:
        return fail("pattern diagnostics must compile out of release builds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
