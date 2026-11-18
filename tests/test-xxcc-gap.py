#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 LATX Project Authors
# SPDX-License-Identifier: MIT
"""Compile the production condition-gap predicate and check its contract."""
import pathlib
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1]).read_text()
def function(name):
    start = source.index('static bool ' + name + '(')
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

analysis = source[source.rindex('static void ft_analyze_direct_xxcc('):]
analysis = analysis[:analysis.index('static bool ft_gap_writes_gpr(')]
assert 'ft_xxcc_gap_is_safe(&fields[gap], lhs, rhs)' in analysis
assert 'ft_direct_gap_is_safe(' not in analysis
code = r'''
#include <assert.h>
#include <stdbool.h>
typedef struct {
 int kind, modrm_mod, modrm_rm_index, modrm_reg_index;
 int direct_cmp_lhs_gpr, direct_cmp_rhs_gpr;
 bool high8;
} FastTemplateFields;
enum { FT_SETCC_RM8, FT_CMOV_R64_RM64, FT_CMOV_R32_RM32,
 FT_CMOV_R16_RM16, MOV_IMM, MOV_REG, MOV_MEM, LEA, NOP, ADD };
static bool ft_modrm_rm_is_high8(const FastTemplateFields *f) { return f->high8; }
'''
code += function('ft_is_xxcc_consumer') + '\n' + function('ft_xxcc_gap_is_safe')
code += r'''
int main(void) {
 FastTemplateFields f = { .modrm_mod=3, .modrm_rm_index=2,
 .modrm_reg_index=2, .direct_cmp_lhs_gpr=0, .direct_cmp_rhs_gpr=1 };
 for (int kind=MOV_IMM; kind<=ADD; ++kind) {
   f.kind=kind; assert(!ft_xxcc_gap_is_safe(&f,0,1));
 }
 for (int kind=FT_SETCC_RM8; kind<=FT_CMOV_R16_RM16; ++kind) {
   f.kind=kind; assert(ft_xxcc_gap_is_safe(&f,0,1));
   f.modrm_mod=0; assert(!ft_xxcc_gap_is_safe(&f,0,1)); f.modrm_mod=3;
   f.modrm_rm_index=0; f.modrm_reg_index=0;
   assert(!ft_xxcc_gap_is_safe(&f,0,1));
   f.modrm_rm_index=1; f.modrm_reg_index=1;
   assert(!ft_xxcc_gap_is_safe(&f,0,1));
   f.modrm_rm_index=2; f.modrm_reg_index=2;
   f.direct_cmp_lhs_gpr=3; assert(!ft_xxcc_gap_is_safe(&f,0,1));
   f.direct_cmp_lhs_gpr=0;
   f.direct_cmp_rhs_gpr=-1; assert(!ft_xxcc_gap_is_safe(&f,0,1));
   assert(ft_xxcc_gap_is_safe(&f,0,-1)); f.direct_cmp_rhs_gpr=1;
 }
 f.kind=FT_SETCC_RM8; f.high8=true; assert(!ft_xxcc_gap_is_safe(&f,0,1));
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xxcc-gap-') as tmp:
    path = pathlib.Path(tmp)
    (path/'test.c').write_text(code)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path/'test.c'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)
print('condition-chain gap contract: PASS')
