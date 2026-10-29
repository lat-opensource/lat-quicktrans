#!/usr/bin/env python3
import pathlib, re, sys
s=pathlib.Path(sys.argv[1]).read_text()
expected={
'CMP_JCC':0,'TEST_JCC':1,'BT_JCC':2,'CQO_IDIV':3,'CMP_SBB':4,
'COMISD_JCC':5,'COMISS_JCC':6,'UCOMISD_JCC':7,'UCOMISS_JCC':8,
'XOR_DIV':9,'CDQ_IDIV':10,'CMP_XX_JCC':11,'TEST_XX_JCC':12,
'BT_XX_JCC':13,'COMISD_XX_JCC':14,'COMISS_XX_JCC':15,
'UCOMISD_XX_JCC':16,'UCOMISS_XX_JCC':17,'CMP_XXCC_CON':18,
'TEST_XXCC_CON':19,'UCOMISD_SETA':20,'ADD_JCC':21,'SUB_JCC':22,
'AND_JCC':23,'OR_JCC':24,'OR_XX_JCC':25,'XOR_JCC':26,
'XOR_XX_JCC':27,'SAR_JCC':28,'AND_XX_JCC':29,'SHR_JCC':30,
'SUB_XX_JCC':31,'SHR_XX_JCC':32,'DEC_JCC':33,
}
for name,shift in expected.items():
    pat=rf'#define FT_INSTPTN_{name}\s+\(1ULL << {shift}\)'
    if not re.search(pat,s):
        print(f'missing legacy bit mapping {name}={shift}',file=sys.stderr);sys.exit(1)
if not re.search(r'static bool ft_instptn_enabled\(uint64_t bit\).*?'
                 r'#ifdef QUICKTRANS_LATU.*?\(void\)bit;.*?return true;.*?'
                 r'return \(option_instptn & bit\) != 0;',s,re.S):
    print('option_instptn adapter or LATU isolation missing',file=sys.stderr);sys.exit(1)
body=s[s.index('static void ft_analyze_direct_jcc_pair('):]
body=body[:body.index('static bool ft_template_uses_x87_top(')]
for token in ('FT_INSTPTN_ADD_JCC','FT_INSTPTN_SUB_JCC','FT_INSTPTN_AND_JCC',
              'FT_INSTPTN_OR_JCC','FT_INSTPTN_XOR_JCC','FT_INSTPTN_DEC_JCC',
              'FT_INSTPTN_SAR_JCC','FT_INSTPTN_SHR_JCC','FT_INSTPTN_CMP_JCC',
              'FT_INSTPTN_TEST_JCC'):
    if token not in body:
        print(f'direct pattern does not select {token}',file=sys.stderr);sys.exit(1)
if 'lhs < 0 || option_bit == 0 || !ft_instptn_enabled(option_bit)' not in body:
    print('direct pattern is not gated by its option bit',file=sys.stderr);sys.exit(1)
if not re.search(r"alu->id == dt_X86_INS_BT.*?alu->modrm_mod == 3.*?"
                 r"FT_DIRECT_BRANCH_BIT_SET.*?FT_INSTPTN_BT_JCC.*?"
                 r"jcc->direct_cmp_width = ft_rex_w\(alu\) \? 64.*?16 : 32",
                 body, re.S):
    print('BT/Jcc must be register-only, bit-gated, and width-correct', file=sys.stderr);sys.exit(1)
emit=(pathlib.Path(sys.argv[1]).parent/'emit-template.inc.c').read_text()
cache=(pathlib.Path(sys.argv[1]).parent/'emit-pattern-cache.inc.c').read_text()
if not re.search(r'FT_DIRECT_BRANCH_BIT_SET.*?direct_bit_index_gpr.*?'
                 r'FT_LA_SRL_D_EMIT.*?FT_LA_ANDI_EMIT', emit, re.S):
    print('BT/Jcc emitter must extract exactly one source bit', file=sys.stderr);sys.exit(1)
print('option_instptn source checks: PASS')
for token in ('ft_analyze_direct_jcc_gap', 'ft_direct_gap_is_safe',
              'FT_INSTPTN_CMP_XX_JCC', 'FT_INSTPTN_TEST_XX_JCC',
              'FT_INSTPTN_BT_XX_JCC', 'FT_INSTPTN_OR_XX_JCC',
              'FT_INSTPTN_XOR_XX_JCC', 'FT_INSTPTN_AND_XX_JCC',
              'FT_INSTPTN_SUB_XX_JCC', 'FT_INSTPTN_SHR_XX_JCC'):
    if token not in s:
        print(f'missing non-adjacent pattern support: {token}', file=sys.stderr)
        sys.exit(1)
for token in ('ft_analyze_direct_xxcc', 'FT_INSTPTN_CMP_XXCC_CON',
              'FT_INSTPTN_TEST_XXCC_CON'):
    if token not in s:
        print(f'missing direct SETcc/CMOVcc analysis: {token}', file=sys.stderr)
        sys.exit(1)
for token in ('ft_analyze_float_xx_jcc', 'FT_INSTPTN_COMISD_XX_JCC',
              'FT_INSTPTN_COMISS_XX_JCC', 'FT_INSTPTN_UCOMISD_XX_JCC',
              'FT_INSTPTN_UCOMISS_XX_JCC', 'direct_float_xx << 10'):
    if token not in s:
        print(f'missing non-adjacent float pattern support: {token}', file=sys.stderr)
        sys.exit(1)
if not re.search(r'cmp->direct_float_xx = true;.*?jcc->direct_float_xx = true;',
                 s, re.S):
    print('float XX pattern must preserve the compare PC and pass a saved result',
          file=sys.stderr)
    sys.exit(1)
if not re.search(r'fields->direct_float_xx.*?cond_lhs = la_a4;', emit, re.S):
    print('float XX Jcc must use the reserved system pattern temporary',
          file=sys.stderr)
    sys.exit(1)
if not re.search(r'#ifdef CONFIG_SOFTMMU\s+int tmp0 = la_a0;\s+'
                 r'int tmp1 = la_a1;\s+int tmp2 = la_a2;', emit):
    print('system direct-condition temporaries must not clobber guest t0-t7',
          file=sys.stderr)
    sys.exit(1)
for token in ('extra_keys', 'direct_cmp_lhs_gpr', 'direct_cmp_rhs_gpr',
              'direct_cmp_width', 'direct_branch_kind',
              'direct_bit_index_gpr', 'direct_bit_index_imm',
              'instptn_div_kind', 'instptn_skip'):
    if token not in cache:
        print(f'instruction pattern cache key misses {token}', file=sys.stderr)
        sys.exit(1)
for token in ('ft_emit_direct_condition', 'case FT_SETCC_RM8:',
              'case FT_CMOV_R64_RM64:'):
    if token not in emit:
        print(f'missing direct condition emission: {token}', file=sys.stderr)
        sys.exit(1)
print('option_instptn extended source checks: PASS')
