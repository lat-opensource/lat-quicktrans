#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import re
import sys


def main() -> int:
    source = pathlib.Path(sys.argv[1]).read_text()
    signature = "bool latx_fast_decode_translate_tb_primary_ex("
    start = source.rindex(signature)
    end = source.index(
        "bool latx_fast_decode_translate_tb_primary(", start,
    )
    primary = source[start:end]
    analysis = "ft_analyze_tb_flags(fields_buf, meta_buf, icount)"
    emit_loop = "for (int i = 0; i < icount; ++i)"

    if primary.count(analysis) != 1:
        print("primary translation must run flag liveness exactly once",
              file=sys.stderr)
        return 1
    if primary.index(analysis) > primary.index(emit_loop):
        print("primary flag liveness must run before instruction emission",
              file=sys.stderr)
        return 1
    if "fields[i].skip_flags = live_def == 0 && masks.use == 0;" not in source:
        print("flag liveness must control per-instruction flag emission",
              file=sys.stderr)
        return 1
    if "option_sys_flag_reduction" in source or "ft_flag_reduction_enabled" in source:
        print("flag reduction must use the existing unconditional analysis",
              file=sys.stderr)
        return 1
    if not re.search(
        r"case dt_X86_INS_RDRAND:\s*"
        r"masks\.def \|= FT_EFLAGS_ALL;",
        source,
    ):
        print("RDRAND flag definitions must participate in liveness",
              file=sys.stderr)
        return 1

    decoder_dir = pathlib.Path(sys.argv[1]).parents[2] / "decoder"
    decoder = "\n".join(
        (decoder_dir / name).read_text()
        for name in ("fast_decoder_ft.inc.c", "fast_decoder_ft_gpr.inc.c")
    )
    emitter_template_info = (pathlib.Path(sys.argv[1]).parent /
                             "template-info.inc.c").read_text()
    decoder_template_info = (pathlib.Path(sys.argv[1]).parents[2] /
                             "templates" / "template-info.inc.c").read_text()
    if "ft_fill_group1_alu_info(&decoded->fields)" not in decoder:
        print("fast decoder Group-1 instructions must publish ALU metadata",
              file=sys.stderr)
        return 1
    for template_info in (emitter_template_info, decoder_template_info):
        if not re.search(
            r"ft_fill_group1_alu_info\([^)]*\).*?"
            r"FT_ALU_ADD.*?FT_ALU_SUB.*?FT_ALU_CMP",
            template_info, re.S,
        ):
            print("Group-1 ALU metadata must use the shared operation mapping",
                  file=sys.stderr)
            return 1
    if not re.search(
        r"if \(count > 1\)\s*\{\s*"
        r"ft_analyze_direct_jcc_pair\(&fields\[count - 2\],\s*"
        r"&fields\[count - 1\],\s*false\);",
        source,
    ):
        print("flag analysis must also analyze direct TEST/JCC pairs",
              file=sys.stderr)
        return 1
    if not re.search(
        r"ft_direct_alu_reg_operands.*?alu->alu_form == FT_ALU_FORM_RM_R.*?"
        r"ft_modrm_rm_is_high8\(alu\).*?ft_modrm_reg_is_high8\(alu\).*?"
        r"direct_cmp_lhs_gpr.*?direct_cmp_width = alu->alu_width",
        source, re.S,
    ):
        print("direct JCC must preserve width and reject high-8 registers",
              file=sys.stderr)
        return 1
    emit = (pathlib.Path(sys.argv[1]).parent / "emit-template.inc.c").read_text()
    if not re.search(
        r"alu->alu_op == FT_ALU_CMP && alu->imm == 0.*?"
        r"FT_ALU_FORM_ACC_IMM.*?lhs = rax_index;.*?"
        r"FT_ALU_FORM_RM_IMM.*?alu->modrm_mod == 3.*?"
        r"ft_modrm_rm_is_high8\(alu\).*?"
        r"lhs = alu->modrm_rm_index;.*?"
        r"direct_cmp_rhs_gpr = rhs;",
        source, re.S,
    ):
        print("CMP zero direct branches must reject memory and high-8 forms",
              file=sys.stderr)
        return 1
    if not re.search(
        r"direct_cmp_width < 64.*?FT_LA_BSTRPICK_D_EMIT.*?"
        r"direct_cmp_width - 1",
        emit, re.S,
    ):
        print("narrow direct JCC operands must be truncated to guest width",
              file=sys.stderr)
        return 1
    if not re.search(
        r"ft_emit_tu_jcc_compare\(.*?cond_lhs, cond_rhs,\s*"
        r"taken_if_equal\)",
        emit, re.S,
    ):
        print("TU direct JCC must compare guest operands without booleanising",
              file=sys.stderr)
        return 1
    condition_masks = (
        ("JE/JNE", r"case dt_X86_INS_JE:.*?return ZF_USEDEF_BIT;"),
        ("JA/JBE", r"case dt_X86_INS_JBE:.*?"
                    r"return CF_USEDEF_BIT \| ZF_USEDEF_BIT;"),
        ("JL/JGE", r"case dt_X86_INS_JL:.*?"
                    r"return OF_USEDEF_BIT \| SF_USEDEF_BIT;"),
        ("JG/JLE", r"case dt_X86_INS_JLE:.*?"
                    r"return OF_USEDEF_BIT \| SF_USEDEF_BIT \| "
                    r"ZF_USEDEF_BIT;"),
    )
    for name, pattern in condition_masks:
        if not re.search(pattern, source, re.S):
            print(f"{name} must use its precise condition flag mask",
                  file=sys.stderr)
            return 1
    if not re.search(
        r"static uint8_t ft_analyze_tb_flags\([^}]*?"
        r"uint8_t pending = FT_EFLAGS_ALL;",
        source, re.S,
    ):
        print("TU-off flag analysis must preserve all TB live-out flags",
              file=sys.stderr)
        return 1
    if not re.search(
        r"latx_fast_analyze_tu_tb_flags\([^}]*?"
        r"uint8_t pending = live_out;.*?"
        r"tu_meta->eflag_out = live_out;",
        source, re.S,
    ):
        print("TU flag analysis must consume and record successor live_out",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
