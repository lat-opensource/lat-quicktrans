#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT
"""Require every legacy primary failure to use the shared failure model."""

import pathlib
import re
import sys
from typing import List


EXPECTED_STAGES = (
    "QUICKTRANS_FAILURE_STAGE_FETCH",
    "QUICKTRANS_FAILURE_STAGE_DECODE",
    "QUICKTRANS_FAILURE_STAGE_TEMPLATE",
    "QUICKTRANS_FAILURE_STAGE_CONSTRAINT",
    "QUICKTRANS_FAILURE_STAGE_EMIT",
    "QUICKTRANS_FAILURE_STAGE_EXIT",
)


def function_bodies(source: str, name: str) -> List[str]:
    bodies = []
    definition = re.compile(r"\bbool\s+" + re.escape(name) + r"\s*\(")
    for match in definition.finditer(source):
        brace = source.find("{", match.end())
        if brace < 0:
            raise ValueError(f"missing function body for {name}")
        depth = 0
        for end in range(brace, len(source)):
            if source[end] == "{":
                depth += 1
            elif source[end] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(source[brace + 1:end])
                    break
        else:
            raise ValueError(f"unterminated function body for {name}")
    return bodies


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} FAST_TRANSLATOR_C", file=sys.stderr)
        return 2

    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    # Check the shared implementation included by both specialized entries.
    body = (pathlib.Path(sys.argv[1]).parent / "primary-translate-body.inc.c").read_text()
    body = body.replace("FT_SPECIALIZED_NAME(", "latx_fast_decode_translate_tb_primary_ex_impl(")
    source = source.replace('#include "primary-translate-body.inc.c"', body, 1)

    bodies = function_bodies(source, "latx_fast_decode_translate_tb_primary_ex")
    if len(bodies) != 2:
        print(f"expected stub and legacy primary bodies, found {len(bodies)}",
              file=sys.stderr)
        return 1

    implementations = function_bodies(
        source, "latx_fast_decode_translate_tb_primary_ex_impl")
    if len(implementations) != 1:
        print("expected one primary implementation", file=sys.stderr)
        return 1
    wrapper = bodies[-1]
    if "*code_size = ft_code_space_error(error);" not in wrapper or \
       "ft_code_space_clear();" not in wrapper:
        print("primary wrapper must preserve resource errors and clear guard",
              file=sys.stderr)
        return 1
    legacy = implementations[0]
    # LATS can ask the caller to retry translation to avoid a code-page
    # deadlock. This is not a decode failure and must not become one.
    retry = re.compile(
        r"#if !defined\(QUICKTRANS_LATU\) && defined\(CONFIG_SOFTMMU\)\s*"
        r"if \(lsenv->tr_data->deadlock_avoidance\) \{\s*"
        r"return false;\s*}\s*#endif"
    )
    legacy = retry.sub("", legacy, count=1)
    # Auxiliary search allocation has its own allocator retry, not a miss.
    legacy = re.sub(
        r"if \(!search_block\) \{\s*"
        r"\*code_size = __GENCODE_ERR_AUX_DATA_OVERFLOW;\s*"
        r"return false;\s*}", "", legacy)
    if "return false;" in legacy:
        print("legacy primary contains an unclassified return false",
              file=sys.stderr)
        return 1
    missing = [stage for stage in EXPECTED_STAGES if stage not in legacy]
    if missing:
        print("legacy primary does not record stages: " + ", ".join(missing),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
