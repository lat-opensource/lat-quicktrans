#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import sys


def main() -> int:
    source = pathlib.Path(sys.argv[1]).read_text()
    templates = pathlib.Path(sys.argv[2]).read_text()
    start = source.index("static void ft_emit_lats_static_call")
    end = source.index("static void ft_emit_lats_direct_link_exit", start)
    static_call = source[start:end]
    required = (
        "FT_LA_PCADDU18I_EMIT(out, scratch_reg, upper);",
        "FT_LA_JIRL_EMIT(out, la_ra, scratch_reg, lower);",
        "FT_LA_BL_EMIT(out, offset);",
        "FT_LA_NOP_EMIT(out);",
    )
    missing = [snippet for snippet in required if snippet not in static_call]

    if missing:
        print("LATS direct-link call slot must occupy eight bytes: " +
              ", ".join(missing), file=sys.stderr)
        return 1
    if "tb->jmp_reset_offset[succ_id] = off + 8;" not in source:
        print("LATS direct-link reset offset must follow the eight-byte slot",
              file=sys.stderr)
        return 1

    direct_start = source.index("static void ft_emit_lats_direct_link_exit")
    direct_end = source.index("#endif", direct_start)
    direct = source[direct_start:direct_end]
    for snippet in (
        "if (!option_lazypc)",
        "tb->next_pc[succ_id] = target;",
        "int pc_reg = la_a5;",
        "ft_emit_store_env(out, pc_reg, lsenv_offset_of_eip(lsenv),",
        "FT_LA_OPCODE_ST_D);",
    ):
        if snippet not in direct:
            print("LATS direct exits must honor option_lazypc: " + snippet,
                  file=sys.stderr)
            return 1

    partial_start = source.index("static int ft_emit_tu_jcc_partial_compare")
    partial_end = source.index("static int ft_emit_tu_jmp_branch_or_zero",
                               partial_start)
    partial = source[partial_start:partial_end]
    for snippet in (
        "ft_emit_direct_link_exit(tb, out, 1, fields->imm64, la_t1);",
        "ft_emit_direct_link_exit(tb, out, 0, pc + fields->size, la_t1);",
    ):
        if snippet not in partial:
            print("LATS TU partial exits must preserve TB linking: " + snippet,
                  file=sys.stderr)
            return 1
    if "ft_emit_tu_call_dispatch_exit" in partial:
        print("LATS TU partial exits must not force dispatcher exits",
              file=sys.stderr)
        return 1

    call_start = templates.index("case FT_CALL_REL32:")
    call_end = templates.index("case FT_CALL_RM64:", call_start)
    direct_call = templates[call_start:call_end]
    if "ft_emit_tu_call_dispatch_exit" in direct_call:
        print("LATS TU direct calls must remain dynamically linkable",
              file=sys.stderr)
        return 1

    jmp_start = templates.index("case FT_JMP_REL32:")
    jmp_end = templates.index("case FT_JMP_RM64:", jmp_start)
    direct_jmp = templates[jmp_start:jmp_end]
    if "ft_emit_tu_call_dispatch_exit" in direct_jmp:
        print("LATS TU direct jumps must remain dynamically linkable",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
