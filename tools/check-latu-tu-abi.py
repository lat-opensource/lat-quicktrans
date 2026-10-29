#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import sys


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def main() -> int:
    exits = pathlib.Path(sys.argv[1]).read_text()
    templates = pathlib.Path(sys.argv[2]).read_text()
    errors = []

    tu_mode = section(exits, "static bool ft_tu_mode_enabled",
                      "static int ft_code_accl_padding")
    for required in (
        "#ifdef QUICKTRANS_LATU",
        'getenv("LATX_TU")',
        "return option_tu != 0;",
    ):
        if required not in tu_mode:
            errors.append(f"TU runtime state is missing host ABI: {required}")
    if 'getenv("LATX_FAST_TRANSLATOR_TU")' in tu_mode:
        errors.append("Quicktrans exits must use the actual host TU state")

    unlink = section(exits, "static int ft_emit_tu_unlink_exit",
                     "static bool ft_tu_direct_jmp_enabled")
    for required in (
        "#ifdef QUICKTRANS_LATU",
        "FT_LA_PCADDI_EMIT(out, la_a0, 0);",
        "ft_emit_far_jump_preserve_a0(out, epilogue, scratch_reg);",
    ):
        if required not in unlink:
            errors.append(f"LATU TU unlink exit is missing: {required}")

    direct = section(exits, "static void ft_prepare_direct_link_exit",
                     "static void ft_emit_direct_link_reset_slot")
    if "tb->canlink[succ_id] = 1;" not in direct:
        errors.append("LATU TU external exits must remain dynamically linkable")
    if "ft_tu_mode_enabled() ? 0 : 1" in direct:
        errors.append("LATU TU mode must not disable external TB linking")

    partial = section(exits, "static int ft_emit_tu_jcc_partial_compare",
                      "static int ft_emit_tu_jmp_branch_or_zero")
    latu_partial = partial.split("#ifdef QUICKTRANS_LATU", 1)[1].split(
        "#else", 1)[0]
    for slot in ("TU_TB_INDEX_NEXT", "TU_TB_INDEX_TARGET"):
        expected = f"tb->tu_jmp[{slot}] = TB_JMP_RESET_OFFSET_INVALID;"
        if expected not in latu_partial:
            errors.append(f"LATU partial JCC must clear {slot}")
    if "set_use_tu_jmp(tb)" in latu_partial:
        errors.append("LATU partial JCC must not enable TU direct linking")

    call = section(templates, "case FT_CALL_REL32:", "case FT_CALL_RM64:")
    if "ft_emit_direct_link_exit(tb, &out, 0, target, la_t1)" not in call or \
       "ft_emit_tu_call_dispatch_exit" in call:
        errors.append("direct CALL must keep the host normal exit ABI")

    indirect_call = section(templates, "case FT_CALL_RM64:",
                            "case FT_JMP_REL32:")
    if "latx_indirect_goto_macro_emit_for_fast(out)" not in indirect_call:
        errors.append("LATU indirect CALL must use the LATU indirect-goto ABI")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
