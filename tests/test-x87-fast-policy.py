#!/usr/bin/env python3
"""Compile the real x87 emitters with a recording sink; no guest execution.
Checks fast-option selection, emitted control flow and LATS/LATU isolation.
Run: python3 tests/test-x87-fast-policy.py
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
def function(path, name):
    text = path.read_text()
    start = text.index('static ', text.index(name + "(") - 30)
    brace = text.index('{', start)
    level = 1
    end = brace + 1
    while level:
        level += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

base = root / 'src/emitter/fast_translator'
source = '\n'.join(function(base / 'emit-x87.inc.c', name) for name in [
    'ft_emit_x87_soft_unary', 'ft_emit_x87_soft_binary_reg',
    'ft_emit_x87_soft_binary_mem', 'ft_emit_x87_soft_sign',
    'ft_emit_x87_soft_stack', 'ft_emit_x87_complex_helper'])
source += '\n#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)\n'
for name in ['ft_soft_x87_guard', 'ft_soft_x87_base', 'ft_soft_x87_slot',
             'ft_soft_x87_slot_direct', 'ft_soft_x87_clear_c1', 'ft_soft_x87_push',
             'ft_soft_x87_pop', 'ft_soft_x87_to_double', 'ft_soft_x87_from_double',
             'ft_soft_x87_normal', 'ft_soft_x87_zero', 'ft_soft_x87_constant', 'ft_soft_x87_load',
             'ft_soft_x87_store', 'ft_soft_x87_cmov', 'ft_soft_x87_scale',
             'ft_soft_x87_compare_operand', 'ft_soft_x87_snan',
             'ft_soft_x87_compare_cold', 'ft_soft_x87_compare',
             'ft_soft_x87_examine', 'ft_soft_x87_memory80', 'ft_soft_x87_fisttp']:
    source += function(base / 'emit-x87-soft-fast.inc.c', name) + '\n'
source += function(base / 'emit-x87.inc.c', 'ft_emit_x87_compare_fallback') + '\n'
source += function(base / 'emit-x87.inc.c', 'ft_emit_x87_integer_fallback') + '\n'
source += function(base / 'emit-x87.inc.c', 'ft_emit_x87_environment_fallback') + '\n'
source += function(base / 'emit-x87.inc.c', 'ft_emit_x87_fx_fallback') + '\n'
source += '\n#endif\n'
ops = sorted(set(re.findall(r'FT_LA_([A-Z0-9_]+)_EMIT', source)))
constants = sorted(set(re.findall(r'\b(?:la_[a-z0-9]+|COND_[A-Z]+|dt_X86_INS_[A-Z0-9]+|FT_X87_[A-Z0-9_]+)\b', source)))
constants = sorted(set(constants) | {'FT_X87_FSTP_M80', 'FT_X87_FCOM_REG', 'FT_X87_FLD_M64', 'FT_X87_FILD_M16', 'FT_X87_FILD_M32', 'FT_X87_FILD_M64'})
helpers = sorted(set(re.findall(r'\b(?:ft_x87_helper_\w+|ft_x87_memory_\w+|helper_fildl_FT0)\b', source)))
header = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
typedef unsigned long target_ulong;
typedef struct {int modrm_rm, id, kind, modrm, modrm_mod, modrm_reg;} FastTemplateFields;
typedef struct {uint32_t *pc;} FastBranchLabel;
typedef struct {uint32_t *pc; FastBranchLabel *label;} FastBranchFixup;
typedef struct {FastBranchLabel slow,done; FastBranchFixup guards[16],done_fix; unsigned count; bool loaded; bool integer_infinity; bool compare_inline; unsigned compare_exponent_mask; FastBranchLabel compare_exponent[2], compare_resume[2], compare_invalid; FastBranchLabel infinity,infinity_resume; FastBranchFixup infinity_fix;} FtSoftX87;
static uint32_t buf[4096];
static void *last_helper;
static unsigned last_pointer_mask, helper_calls;
static int operands[4096][5];
static unsigned option_soft_fpu_fast;
static int option_soft_fpu = 1;
static int lsenv, ft_vscratch = 40;
static bool use_static_context = true;
static bool scs_enabled(void) {return use_static_context;}
static void *ft_x87_binary_helpers[3][6];
#define lsenv_offset_of_fpr(e,n) (128 + (n)*16)
#define lsenv_offset_of_top(e) 0
#define lsenv_offset_of_status_word(e) 4
#define lsenv_offset_of_control_word(e) 6
#define lsenv_offset_of_nofp(e) 32
#define lsenv_offset_of_fp_status(e) 48
#define lsenv_offset_of_mxcsr(e) 64
#define FT_LA_OPCODE_LD_WU 1
#define FT_LA_OPCODE_ST_W 2
#define helper_fxsave ((void *)5)
#define helper_fxrstor ((void *)6)
#define ft_emit_load_env(out,reg,off,op) dummy(out)
#define ft_emit_store_env(out,reg,off,op) dummy(out)
#define ft_emit_mxcsr_flags_from_fcsr(out,reg) do {assert(last_helper==NULL);dummy(out);} while(0)
#define ft_emit_lats_softfpu_mxcsr(out,reg) do {assert(last_helper==helper_fxrstor);dummy(out);} while(0)
typedef struct {unsigned char float_rounding_mode; unsigned short float_exception_flags;} float_status;
#define lsenv_offset_of_tag_word(e) 16
static bool ft_emit_x87_mark_denormal_operand(uint32_t **out,int reg,bool wide){return true;}
static bool ft_offset_fits_imm12(int n) {return n >= -2048 && n < 2048;}
static void record(uint32_t **out, int op, const int *args, size_t n) {
    int i = *out-buf; assert(n <= 5); for(size_t j=0;j<n;j++)operands[i][j]=args[j];
    *(*out)++=op;
}
static void dummy(uint32_t **out){*(*out)++=999;}
#define ft_emit_nofp_helper_prologue(out) (dummy(out),true)
#define ft_emit_nofp_helper_epilogue(out, context) dummy(out)
#define ft_emit_default_helper_call(out, helper, mask, context) do {last_helper=(helper);last_pointer_mask=(mask);helper_calls++;dummy(out);} while(0)
#define helper_fsincos ((void *)3)
#define ft_emit_default_helper_prologue(out, fprs) (dummy(out),true)
#define ft_emit_default_helper_epilogue(out, ctx, fprs) dummy(out)
#define helper_fildll_ST0 0
#define helper_fldenv 0
#define ft_fits_simm12(v) ((v)>=-2048 && (v)<=2047)
#define helper_fistt_ST0 0
#define helper_fisttl_ST0 0
#define helper_fisttll_ST0 0
#define ft_emit_helper_prologue(out) dummy(out)
#define ft_emit_helper_epilogue(out) dummy(out)
#define ft_emit_cpu_env_ptr(out, reg) dummy(out)
#define ft_emit_host_call(out, func, mask) dummy(out)
#define ft_emit_x87_helper(out, func) do {last_helper=(func); dummy(out);} while(0)
#define ft_emit_lats_nofp_helper(out, func) do {last_helper=(func); dummy(out);} while(0)
static bool ft_emit_rip_or_mem_addr(uint32_t **out,const FastTemplateFields *f,target_ulong pc,int *addr){*addr=30;return true;}
static int ft_mem_access_offset(const FastTemplateFields *f,int addr){return 0;}
'''
header += '\nenum {' + ','.join(constants) + '};\n'
header += '\nenum {' + ','.join('OP_'+op for op in ops) + '};\n'
header += '\n'.join('#define '+h+' 0' for h in helpers)+'\n'
for op in ops:
    header += '#define FT_LA_'+op+'_EMIT(out,...) record(out,OP_'+op+', (int[]){__VA_ARGS__},sizeof((int[]){__VA_ARGS__})/sizeof(int))\n'
header += r'''
#define FT_BRANCH_B 105
#define FT_BRANCH_BEQ 100
#define FT_BRANCH_BNE 101
#define FT_BRANCH_BLTU 102
#define FT_BRANCH_BGEU 103
#define FT_BRANCH_BGE 104
static void ft_emit_branch_placeholder(uint32_t **out, FastBranchFixup *f,int op,int a,int b,FastBranchLabel *l){f->pc=*out; f->label=l; record(out,op,(int[]){a,b,0},3);}
static void ft_bind_branch_label(FastBranchLabel *l,uint32_t *out){l->pc=out;}
static void ft_resolve_branch_fixup(FastBranchFixup *f){operands[f->pc-buf][2]=f->label->pc-f->pc;}
'''
header += r'''
#define FT_LA_OPCODE_FCMP_COND_D 0
static int ft_fcmp_cond(int op,int cc,int a,int b,int cond){return 200+cond;}
static void ft_emit_raw(uint32_t **out,int op){*(*out)++=op;}
static int ft_scratch_avoid3(int a,int b,int c){return la_t4;}
static void ft_emit_li64(uint32_t **out,int r,uint64_t v){FT_LA_ORI_EMIT(out,r,la_zero,(int)v);}
static bool ft_x87_fild_width(int kind,int *width){
    if(kind==FT_X87_FILD_M16){*width=16;return true;}
    if(kind==FT_X87_FILD_M32){*width=32;return true;}
    if(kind==FT_X87_FILD_M64){*width=64;return true;}
    return false;
}
'''
main = r'''
static void no_helper(uint32_t *out){for(uint32_t *p=buf;p<out;p++)assert(*p!=999 && *p!=100);}


/* Interpret the generated integer guards; floating conversion begins after them. */
static bool takes_slow(uint32_t *out,int exponent,uint64_t mantissa,int rounding){
    uint64_t r[128]={0};r[la_s0]=1024;
    for(int i=0;i<out-buf;i++){
        int *a=operands[i];
        switch(buf[i]){
        case OP_LD_W:r[a[0]]=0;break;
        case OP_LD_HU:r[a[0]]=exponent;break;
        case OP_LD_D:r[a[0]]=mantissa;break;
        case OP_LD_BU:r[a[0]]=rounding;break;
        case OP_ORI:r[a[0]]=r[a[1]]|a[2];break;
        case OP_ADDI_D:r[a[0]]=r[a[1]]+a[2];break;
        case OP_ADD_D:r[a[0]]=r[a[1]]+r[a[2]];break;
        case OP_ANDI:r[a[0]]=r[a[1]]&a[2];break;
        case OP_AND:r[a[0]]=r[a[1]]&r[a[2]];break;
        case OP_XORI:r[a[0]]=r[a[1]]^a[2];break;
        case OP_SLLI_D:r[a[0]]=r[a[1]]<<a[2];break;
        case OP_SRLI_D:r[a[0]]=r[a[1]]>>a[2];break;
        case OP_SLTU:r[a[0]]=r[a[1]]<r[a[2]];break;
        case OP_BSTRPICK_D:case OP_BSTRPICK_W:r[a[0]]=(r[a[1]]>>a[3])&((1ul<<(a[2]-a[3]+1))-1);break;
        case 100:if(r[a[0]]==r[a[1]]){if(a[2])i+=a[2]-1;else return true;}break;
        case 101:if(r[a[0]]!=r[a[1]]){if(a[2])i+=a[2]-1;else return true;}break;
        case 104:if((int64_t)r[a[0]]>=(int64_t)r[a[1]])return true;break;
        case OP_VLD:return false;
        default:assert(0);
        }
    }
    return false;
}
static void check_stack(uint32_t *out,FastTemplateFields f,int top){
    long regs[128]={0}, vec[128]={0}, slots[8], tags[8], expected[8], expected_tags[8];
    int newtop=top, index=f.modrm&7, n=(top+index)&7; long status=0xffff;
    regs[la_s0]=1024;
    for(int i=0;i<8;i++){slots[i]=expected[i]=0x1000+i;tags[i]=expected_tags[i]=i&1;}
    if(f.kind==FT_X87_FLD_REG){newtop=(top+7)&7;expected[newtop]=slots[n];expected_tags[newtop]=0;}
    if(f.kind==FT_X87_FST_REG||f.kind==FT_X87_FSTP_REG)expected[n]=slots[top];
    if(f.kind==FT_X87_FXCH){expected[n]=slots[top];expected[top]=slots[n];}
    if(f.kind==FT_X87_FFREE)expected_tags[n]=1;
    if(f.kind==FT_X87_FSTP_REG||f.id==dt_X86_INS_FFREEP){newtop=(top+1)&7;expected_tags[top]=1;}
    if(f.kind==FT_X87_TOP_ADJ)newtop=(top+(f.id==dt_X86_INS_FDECSTP?7:1))&7;
    long actual_top=top;
    for(int i=0;i<out-buf;i++){
        int *a=operands[i]; long addr;
        switch(buf[i]){
        case OP_LD_W:assert(regs[a[1]]+a[2]==1024);regs[a[0]]=actual_top;break;
        case OP_LD_HU:assert(regs[a[1]]+a[2]==1028);regs[a[0]]=status;break;
        case OP_ST_W:assert(regs[a[1]]+a[2]==1024);actual_top=regs[a[0]];break;
        case OP_ST_H:assert(regs[a[1]]+a[2]==1028);status=regs[a[0]];break;
        case OP_ST_B:addr=regs[a[1]]+a[2]-1040;assert(addr>=0&&addr<8);tags[addr]=regs[a[0]];break;
        case OP_ADDI_D:regs[a[0]]=regs[a[1]]+a[2];break;
        case OP_ANDI:regs[a[0]]=regs[a[1]]&a[2];break;
        case OP_ORI:regs[a[0]]=regs[a[1]]|a[2];break;
        case OP_SLLI_D:regs[a[0]]=regs[a[1]]<<a[2];break;
        case OP_ADD_D:regs[a[0]]=regs[a[1]]+regs[a[2]];break;
        case OP_BSTRINS_D:{unsigned long mask=((1ul<<(a[2]-a[3]+1))-1)<<a[3];regs[a[0]]=(regs[a[0]]&~mask)|((regs[a[1]]<<a[3])&mask);break;}
        case OP_VLD:addr=regs[a[1]]+a[2]-1152;assert(addr>=0&&addr<128&&addr%16==0);vec[a[0]]=slots[addr/16];break;
        case OP_VST:addr=regs[a[1]]+a[2]-1152;assert(addr>=0&&addr<128&&addr%16==0);slots[addr/16]=vec[a[0]];break;
        default:assert(0);
        }
    }
    assert(actual_top==newtop);
    assert(status==(f.kind==FT_X87_TOP_ADJ?(0xffff&~0x4700):0xffff));
    for(int i=0;i<8;i++){assert(slots[i]==expected[i]);assert(tags[i]==expected_tags[i]);}
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void check_examine(uint32_t *out, int top, int tag, uint16_t high, uint64_t low, uint16_t status){
    uint64_t r[128]={0};r[la_s0]=1024;uint16_t actual=0;int steps=0;
    for(int i=0;i<out-buf;i++){
        assert(++steps<80);int *a=operands[i];uint64_t address=r[a[1]]+a[2];
        switch(buf[i]){
        case OP_LD_W:assert(address==1024);r[a[0]]=top;break;
        case OP_LD_BU:assert(address==1040+top);r[a[0]]=tag;break;
        case OP_LD_HU:r[a[0]]=address==1028?status:high;break;
        case OP_LD_D:assert(address==1152+top*16);r[a[0]]=low;break;
        case OP_ST_H:assert(address==1028);actual=r[a[0]];break;
        case OP_ADD_D:r[a[0]]=r[a[1]]+r[a[2]];break;
        case OP_SLLI_D:r[a[0]]=r[a[1]]<<a[2];break;
        case OP_SRLI_D:r[a[0]]=r[a[1]]>>a[2];break;
        case OP_ORI:r[a[0]]=r[a[1]]|a[2];break;
        case OP_OR:r[a[0]]=r[a[1]]|r[a[2]];break;
        case OP_BSTRPICK_D:r[a[0]]=(r[a[1]]>>a[3])&((1ul<<(a[2]-a[3]+1))-1);break;
        case OP_BSTRINS_D:{uint64_t mask=((1ul<<(a[2]-a[3]+1))-1)<<a[3];r[a[0]]=(r[a[0]]&~mask)|((r[a[1]]<<a[3])&mask);break;}
        case 100:if(r[a[0]]==r[a[1]])i+=a[2]-1;break;
        case 101:if(r[a[0]]!=r[a[1]])i+=a[2]-1;break;
        case 105:i+=a[2]-1;break;
        default:assert(0);
        }
    }
    unsigned cls=0,exp=high&0x7fff;
    if(tag)cls=0x4100;
    else if(!exp)cls=low?0x4400:0x4000;
    else if(low>>63)cls=exp==0x7fff?(low==UINT64_C(0x8000000000000000)?0x500:0x100):0x400;
    assert(actual==((status&0xb8ff)|((high>>15)<<9)|cls));
}
#endif
int main(void){
    uint32_t *out;
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    const int compare_kinds[]={FT_X87_FCOM_M32,FT_X87_FCOM_M64,
                               FT_X87_FI_BIN_M16,FT_X87_FI_BIN_M32};
    for(int i=0;i<4;i++)for(int pop=0;pop<2;pop++) {
        FastTemplateFields f={.kind=compare_kinds[i],.modrm_reg=2+pop};
        out=buf;helper_calls=0;
        assert(ft_emit_x87_compare_fallback(&out,&f));
        assert(helper_calls==1 && last_pointer_mask==1);
        if(pop)assert(out[-7]==OP_LD_W && out[-1]==OP_ST_W);
        else assert(out[-1]==999);
        use_static_context=false;out=buf;helper_calls=0;
        assert(!ft_emit_x87_compare_fallback(&out,&f));
        assert(out==buf && helper_calls==0);
        use_static_context=true;
    }
    const int fisttp_kinds[]={FT_X87_FISTTP_M16,FT_X87_FISTTP_M32,FT_X87_FISTTP_M64};
    const int fisttp_stores[]={OP_ST_H,OP_ST_W,OP_ST_D};
    for(int i=0;i<3;i++) {
        FastTemplateFields f={.kind=fisttp_kinds[i]};out=buf;
        assert(ft_soft_x87_fisttp(&out,&f,0));
        /* Four context/call markers, one store, then seven pop operations.
         * No conditional guard or second copy of a helper path. */
        assert(out-buf==12);
        for(int j=0;j<4;j++)assert(buf[j]==999);
        assert(buf[4]==fisttp_stores[i] && operands[4][0]==la_a0);
        assert(buf[5]==OP_LD_W && buf[11]==OP_ST_W);
        use_static_context=false;out=buf;
        assert(!ft_soft_x87_fisttp(&out,&f,0) && out==buf);
        use_static_context=true;f.modrm_mod=3;
        assert(!ft_soft_x87_fisttp(&out,&f,0) && out==buf);
    }
#endif
    for(int soft=0;soft<2;soft++)for(int fast=0;fast<2;fast++) {
        option_soft_fpu=soft;option_soft_fpu_fast=fast;out=buf;
        ft_emit_x87_complex_helper(&out,(void *)1,(void *)2);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        assert(last_helper==(void *)(uintptr_t)(soft && fast ? 2 : 1));
#else
        assert(last_helper==(void *)1);
#endif
        out=buf;ft_emit_x87_complex_helper(&out,(void *)1,helper_fsincos);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        assert(last_helper==(soft && fast ? helper_fsincos : (void *)1));
        assert(out-buf==(soft && fast ? 4 : 1));
#else
        assert(last_helper==(void *)1 && out-buf==1);
#endif
    }
    option_soft_fpu=1;
    const int operations[]={FT_X87_REG_ADD,FT_X87_REG_MUL,FT_X87_REG_SUB,FT_X87_REG_SUBR,FT_X87_REG_DIV,FT_X87_REG_DIVR};
    const unsigned masks[2][6]={{2,0x1000,0x20000,0x80000,4,0x10},{1,0x2000,0x40000,0x100000,8,0x20}};
    /* Actual op enums must have the production order, not alphabetical order. */
    for(int mode=0;mode<3;mode++)for(int op=0;op<6;op++)for(int idx=0;idx<8;idx++){
        option_soft_fpu_fast=masks[mode==2][op]; out=buf;
        ft_emit_x87_soft_binary_reg(&out,idx,operations[op],mode);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        no_helper(out); assert(out-buf==(mode==2?24:18));
#else
        assert(buf[0]==999);
#endif
        option_soft_fpu_fast=0;out=buf;ft_emit_x87_soft_binary_reg(&out,idx,operations[op],mode);assert(buf[0]==999);
    }
    for(int sq=0;sq<2;sq++){
        option_soft_fpu_fast=sq?0x10000:0x4000;out=buf;ft_emit_x87_soft_unary(&out,sq);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        no_helper(out);assert(out-buf==11);
#endif
        option_soft_fpu_fast=sq?0x4000:0x10000;out=buf;ft_emit_x87_soft_unary(&out,sq);assert(buf[0]==999);
    }
    for(int integer=0;integer<2;integer++)for(int width=integer?16:32;width<=64;width*=2){
        if(integer && width==64)continue;
        for(int op=0;op<8;op++){
            if(op==2||op==3)continue;
            FastTemplateFields f={0};option_soft_fpu_fast=~0u;out=buf;
            assert(ft_emit_x87_soft_binary_mem(&out,&f,0,width,integer,op));
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
            no_helper(out); assert(out-buf==13+(integer||width==32));
#endif
            option_soft_fpu_fast=0;out=buf;assert(ft_emit_x87_soft_binary_mem(&out,&f,0,width,integer,op));assert(buf[0]==999);
        }
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    const int ids[]={dt_X86_INS_FCMOVB,dt_X86_INS_FCMOVE,dt_X86_INS_FCMOVBE,dt_X86_INS_FCMOVU,dt_X86_INS_FCMOVNB,dt_X86_INS_FCMOVNE,dt_X86_INS_FCMOVNBE,dt_X86_INS_FCMOVNU};
    for(int c=0;c<8;c++)for(int idx=0;idx<8;idx++){
        FastTemplateFields f={idx,ids[c]};out=buf;assert(ft_soft_x87_cmov(&out,&f));assert(out-buf==9);
        assert(buf[0]==OP_SETX86J && buf[1]==100 && operands[1][2]==8);
        /* Execute address operations for every TOP. A false condition skips all memory. */
        for(int top=0;top<8;top++){
            long regs[128]={0};regs[la_s0]=1024;
            for(int i=2;i<7;i++){
                int *a=operands[i];
                switch(buf[i]){
                case OP_LD_W:regs[a[0]]=top;break;
                case OP_ADDI_D:regs[a[0]]=regs[a[1]]+a[2];break;
                case OP_ANDI:regs[a[0]]=regs[a[1]]&a[2];break;
                case OP_SLLI_D:regs[a[0]]=regs[a[1]]<<a[2];break;
                case OP_ADD_D:regs[a[0]]=regs[a[1]]+regs[a[2]];break;
                case OP_ALSL_D:regs[a[0]]=(regs[a[1]]<<(a[3]+1))+regs[a[2]];break;
                default:assert(0);
                }
            }
            assert(regs[la_t0]==1024+16*top);
            assert(regs[la_t1]==1024+16*((top+idx)&7));
            assert(buf[7]==OP_VLD && operands[7][1]==la_t1);
            assert(buf[8]==OP_VST && operands[8][1]==la_t0);
        }
    }
#endif

    for(int negate=0;negate<2;negate++){
        option_soft_fpu_fast=1;out=buf;ft_emit_x87_soft_sign(&out,negate);
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        no_helper(out);assert(out-buf==6+negate);
#endif
        option_soft_fpu_fast=0;out=buf;ft_emit_x87_soft_sign(&out,negate);assert(buf[0]==999);
    }
    const int kinds[]={FT_X87_FLD_REG,FT_X87_FST_REG,FT_X87_FSTP_REG,FT_X87_FXCH,FT_X87_FFREE,FT_X87_FFREE,FT_X87_TOP_ADJ,FT_X87_TOP_ADJ};
    const int modrms[]={0xc0,0xd0,0xd8,0xc8,0xc0,0xc0,0,0};
    for(int k=0;k<8;k++)for(int idx=0;idx<8;idx++){
        FastTemplateFields f={.kind=kinds[k],.modrm=modrms[k]+idx,.id=k==5?dt_X86_INS_FFREEP:k==6?dt_X86_INS_FINCSTP:k==7?dt_X86_INS_FDECSTP:-1};
        option_soft_fpu_fast=0;out=buf;assert(!ft_emit_x87_soft_stack(&out,&f));assert(out==buf);
        option_soft_fpu_fast=1;out=buf;
        if(k==1||k==2){assert(!ft_emit_x87_soft_stack(&out,&f));assert(out==buf);}
        option_soft_fpu_fast=0x800000;out=buf;
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
        assert(ft_emit_x87_soft_stack(&out,&f));no_helper(out);
        for(int top=0;top<8;top++)check_stack(out,f,top);
#else
        assert(!ft_emit_x87_soft_stack(&out,&f));assert(out==buf);
#endif
    }
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    const int load_kinds[]={FT_X87_FLD_M32,FT_X87_FLD_M64,FT_X87_FILD_M16,FT_X87_FILD_M32,FT_X87_FILD_M64};
    for(int k=0;k<5;k++){
        FtSoftX87 st={0}; FastTemplateFields f={.kind=load_kinds[k]};out=buf;
        assert(ft_soft_x87_load(&out,&st,&f,0));assert(st.loaded);
        if(k<4){assert(st.count==0);no_helper(out);}else{assert(st.count>0);}
    }
    const int store_kinds[]={FT_X87_FST_M32,FT_X87_FST_M64,FT_X87_FSTP_M32,FT_X87_FSTP_M64,FT_X87_FIST_M32};
    for(int k=0;k<5;k++){
        FtSoftX87 st={0}; FastTemplateFields f={.kind=store_kinds[k]};out=buf;option_soft_fpu_fast=0;
        assert(!ft_soft_x87_store(&out,&st,&f,0));assert(out==buf);
        option_soft_fpu_fast=~0u;assert(ft_soft_x87_store(&out,&st,&f,0));
        if(k<4){assert(st.count==0);no_helper(out);}else{assert(st.count>0);}
    }
    /* FST m64 must address the same 16-byte slot at every valid TOP. */
    {
        FtSoftX87 st={0}; FastTemplateFields f={.kind=FT_X87_FST_M64};
        out=buf; assert(ft_soft_x87_store(&out,&st,&f,0));
        for(unsigned top=0;top<8;top++) {
            uint64_t regs[128]={0}; regs[la_s0]=0x100000;
            int i=0;
            for(;i<out-buf;i++) {
                int *a=operands[i];
                if(buf[i]==OP_LD_W) regs[a[0]]=top;
                else if(buf[i]==OP_ALSL_D)
                    regs[a[0]]=(regs[a[1]]<<(a[3]+1))+regs[a[2]];
                else break;
            }
            assert(i>0 && regs[la_t0]==regs[la_s0]+top*16);
        }
    }
    for(int helper_id=1;helper_id<=4;helper_id++)
    for(int data32=0;data32<2;data32++) {
        void *helper=(void *)(uintptr_t)helper_id;
        FastTemplateFields f={0};out=buf;use_static_context=false;
        assert(!ft_emit_x87_environment_fallback(&out,&f,0,data32,helper));assert(out==buf);
        use_static_context=true;assert(ft_emit_x87_environment_fallback(&out,&f,0,data32,helper));
        assert(buf[0]==OP_ADDI_D && operands[0][0]==la_a2);
        int address_copy=0,format_arg=0;
        for(uint32_t *p=buf;p<out;p++) {
            int i=p-buf;
            if(*p==OP_OR && operands[i][0]==la_a1) {
                assert(operands[i][1]==la_a2);address_copy++;
            }
            if(*p==OP_ADDI_D && operands[i][0]==la_a2 && operands[i][1]==la_zero) {
                assert(address_copy==1 && operands[i][2]==data32);format_arg++;
            }
        }
        assert(address_copy==1 && format_arg==1);
        assert(last_helper==helper && last_pointer_mask==3);
    }
    for (int restore=0; restore<2; restore++) {
        FastTemplateFields f={0};out=buf;use_static_context=false;
        assert(!ft_emit_x87_fx_fallback(&out,&f,0,restore));assert(out==buf);
        use_static_context=true;last_helper=NULL;
        assert(ft_emit_x87_fx_fallback(&out,&f,0,restore));
        assert(buf[0]==OP_ADDI_D && operands[0][0]==la_a2);
        assert(buf[2]==OP_OR && operands[2][0]==la_a1 && operands[2][1]==la_a2);
        assert(last_helper==(restore?helper_fxrstor:helper_fxsave));
        assert(last_pointer_mask==1);
    }
    use_static_context=true;
    {FastTemplateFields f={.kind=FT_X87_FILD_M64};out=buf;
        use_static_context=false;
        assert(!ft_emit_x87_integer_fallback(&out,&f,0));assert(out==buf);
        use_static_context=true;
        assert(ft_emit_x87_integer_fallback(&out,&f,0));
        assert(buf[0]==OP_MOVFR2GR_D && operands[0][0]==la_a2 && operands[0][1]==ft_vscratch+1);
        assert(buf[2]==OP_OR && operands[2][0]==la_a1 && operands[2][1]==la_a2);
        assert(last_helper==helper_fildll_ST0 && last_pointer_mask==1);
        for(uint32_t *p=buf;p<out;p++)assert(*p!=OP_LD_D && *p!=OP_LD_W && *p!=OP_ST_D);
    }
    const int fallback_kinds[]={FT_X87_FIST_M16,FT_X87_FIST_M32,FT_X87_FISTP_M16,FT_X87_FISTP_M64,FT_X87_FISTP_M32};
    for(int k=0;k<5;k++){
        FastTemplateFields f={.kind=fallback_kinds[k]};out=buf;use_static_context=false;
        assert(!ft_emit_x87_integer_fallback(&out,&f,0));assert(out==buf);
        use_static_context=true;assert(ft_emit_x87_integer_fallback(&out,&f,0));
        int loads=0;for(uint32_t *p=buf;p<out;p++)loads+=*p==OP_LD_W;
        assert(loads==(k>=2?1:0));
        if(k==4){
            assert(last_helper==ft_x87_helper_fistl && last_pointer_mask==1);
            int stores=0;for(int i=0;i<out-buf;i++)if(buf[i]==OP_ST_W && operands[i][0]==la_a0)stores++;
            assert(stores==1);
        }
    }
    const int constants_ids[]={dt_X86_INS_FLDZ,dt_X86_INS_FLD1,dt_X86_INS_FLDPI,dt_X86_INS_FLDLN2,dt_X86_INS_FLDL2E,dt_X86_INS_FLDL2T,dt_X86_INS_FLDLG2};
    for(int k=0;k<7;k++){FtSoftX87 st={0};out=buf;assert(ft_soft_x87_constant(&out,&st,constants_ids[k]));assert(st.count==0);no_helper(out);}
#endif

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    const int fist_kinds[]={FT_X87_FIST_M16,FT_X87_FIST_M32,FT_X87_FISTP_M16,FT_X87_FISTP_M32,FT_X87_FISTP_M64};
    for(int k=0;k<5;k++){
        FtSoftX87 st={0};FastTemplateFields f={.kind=fist_kinds[k]};option_soft_fpu_fast=~0u;out=buf;
        assert(ft_soft_x87_store(&out,&st,&f,0));assert(st.count==2);
        int limit=0x3fff+(k==4?52:24);
        for(int round=0;round<8;round++){
            /* Zero, a fractional value and just below the exponent limit. */
            assert(takes_slow(out,0,0,round)==((round&4)!=0));
            assert(takes_slow(out,0x3fff,UINT64_C(0xc000000000000000),round)==((round&4)!=0));
            assert(takes_slow(out,limit-1,~UINT64_C(0),round)==((round&4)!=0));
            assert(takes_slow(out,limit,UINT64_C(0x8000000000000000),round));
        }
    }
    {
        FtSoftX87 st={0};out=buf;ft_soft_x87_compare_operand(&out,&st,la_s0,true);assert(st.count==2);
        assert(!takes_slow(out,0,0,0));
        assert(!takes_slow(out,0,1,0));
        assert(!takes_slow(out,0x3fff,UINT64_C(0x8000000000000001),0));
        assert(!takes_slow(out,1,UINT64_C(0x8000000000000000),0));
        assert(!takes_slow(out,0x7ffe,~UINT64_C(0),0));
        assert(takes_slow(out,1,1,0));
        assert(!takes_slow(out,0x7fff,UINT64_C(0x8000000000000000),0));
        assert(!takes_slow(out,0xffff,UINT64_C(0x8000000000000000),0));
        assert(takes_slow(out,0x7fff,0,0));
        assert(takes_slow(out,0x7fff,UINT64_C(0xc000000000000000),0));
        st=(FtSoftX87){0};out=buf;
        ft_soft_x87_compare_operand(&out,&st,la_s0,false);
        assert(st.count==2 && out-buf==10);
        assert(takes_slow(out,0x7fff,UINT64_C(0x8000000000000000),0));
        assert(!takes_slow(out,0x3fff,UINT64_C(0x8000000000000000),0));
        st=(FtSoftX87){.integer_infinity=true};out=buf;
        ft_soft_x87_compare_operand(&out,&st,la_s0,false);
        /* Only the exponent branch destination changes on the finite path. */
        assert(st.count==1 && out-buf==10);
    }
    {
        FtSoftX87 st={0};out=buf;option_soft_fpu_fast=1;assert(!ft_soft_x87_scale(&out,&st));assert(out==buf);
        option_soft_fpu_fast=0x8000;assert(ft_soft_x87_scale(&out,&st));assert(st.count==0);no_helper(out);
        int trunc=-1,scale=-1;for(int i=0;i<out-buf;i++){if(buf[i]==OP_FTINTRZ_L_D)trunc=i;if(buf[i]==OP_FSCALEB_D)scale=i;}
        assert(trunc>=0 && scale==trunc+1);
    }
    const int cmp_kinds[]={FT_X87_FCOM_REG,FT_X87_FCOMP_REG,FT_X87_FCOMI_REG,FT_X87_FCOMIP_REG,FT_X87_FCOMPP,FT_X87_FUCOMPP,FT_X87_FTST,FT_X87_FCOM_M32,FT_X87_FCOM_M64,FT_X87_FI_BIN_M16,FT_X87_FI_BIN_M32};
    for(int k=0;k<11;k++){
        for(int quiet=0;quiet<2;quiet++){
            FtSoftX87 st={0};FastTemplateFields f={.kind=cmp_kinds[k],.id=quiet?dt_X86_INS_FUCOM:0,.modrm_rm=1,.modrm_reg=2};
            bool flags=k==2||k==3;unsigned mask=flags?(quiet?0x8000000:0x4000000):(quiet?0x2000000:0x1000000);
            option_soft_fpu_fast=~mask;out=buf;assert(!ft_soft_x87_compare(&out,&st,&f,0));assert(out==buf);
            option_soft_fpu_fast=mask;assert(ft_soft_x87_compare(&out,&st,&f,0));
            int writes=0,flagwrites=0;for(int i=0;i<out-buf;i++){writes+=buf[i]==OP_ST_H;flagwrites+=buf[i]==OP_X86MTFLAG;}
            assert(writes==!flags && flagwrites==flags);
            ft_emit_branch_placeholder(&out,&st.done_fix,FT_BRANCH_B,0,0,&st.done);
            ft_soft_x87_compare_cold(&out,&st,&f);
            for(uint32_t *p=buf;p<out;p++)assert(*p!=999);
            assert(st.count==0);
        }
    }
#endif

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
    {
        FtSoftX87 st={0};out=buf;assert(ft_soft_x87_examine(&out,&st));assert(st.count==0);
        const uint16_t exps[]={0,1,0x3fff,0x7ffe,0x7fff};
        const uint64_t lows[]={0,1,UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000001),UINT64_C(0xc000000000000000),UINT64_MAX};
        for(int top=0;top<8;top++)for(int tag=0;tag<2;tag++)for(int sign=0;sign<2;sign++)
          for(int e=0;e<5;e++)for(int m=0;m<7;m++)for(int status=0;status<2;status++)
            check_examine(out,top,tag,exps[e]|(sign<<15),lows[m],status?0xffff:0);
    }
    for(int load=0;load<2;load++){
        FtSoftX87 st={0};FastTemplateFields f={.kind=load?FT_X87_FLD_M80:FT_X87_FSTP_M80};
        out=buf;option_soft_fpu_fast=~0u;assert(ft_soft_x87_memory80(&out,&st,&f,0));
        assert(st.count==0);no_helper(out);assert(out-buf<=20);
        /* Store high half first, as legacy does; both guest accesses precede TOP. */
        int first=-1,second=-1,top_write=-1;
        for(int i=0;i<out-buf;i++){
            if(operands[i][1]==la_t1 && (buf[i]==OP_ST_H||buf[i]==OP_ST_D||buf[i]==OP_LD_D||buf[i]==OP_LD_HU)){
                if(first<0)first=i;else second=i;
            }
            if(buf[i]==OP_ST_W)top_write=i;
        }
        assert(first>=0&&second>first&&top_write>second);
        assert(operands[first][2]==(load?0:8));assert(operands[second][2]==(load?8:0));
        if(!load){out=buf;option_soft_fpu_fast=1;assert(!ft_soft_x87_memory80(&out,&st,&f,0));assert(out==buf);}
    }
#endif
    puts("x87 fast policy: PASS");
}
'''
# Arithmetic op indexes are used in mask/helper arrays in production.
order=['FT_X87_REG_ADD','FT_X87_REG_MUL','FT_X87_REG_SUB','FT_X87_REG_SUBR','FT_X87_REG_DIV','FT_X87_REG_DIVR']
header=header.replace('enum {'+','.join(constants)+'};', 'enum {'+','.join(x+'='+str(i) for i,x in enumerate(order))+'};\nenum {'+','.join(x for x in constants if x not in order)+'};')
with tempfile.TemporaryDirectory(prefix='qt-x87-policy-') as td:
    p=Path(td)/'test.c';p.write_text(header+source+main)
    for defines in [['CONFIG_SOFTMMU','CONFIG_LATX_OPT_NOFP'],['CONFIG_SOFTMMU'],['CONFIG_SOFTMMU','QUICKTRANS_LATU']]:
        exe=Path(td)/'test'
        subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O2',*[f'-D{d}' for d in defines],str(p),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)

# The fast comparison wrapper may restore C1 only, never mask other changes.
wrapper = '\n'.join(function(base / 'emit-x87-helper.inc.c', name) for name in ['ft_x87_legacy_unordered_kind','ft_x87_legacy_snan','ft_x87_fast_unordered','ft_x87_helper_compare_reg_fast'])
with tempfile.TemporaryDirectory(prefix='qt-x87-c1-') as td:
    p = Path(td) / 'test.c'
    p.write_text('''#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#define CC_C 1
#define CC_P 4
#define CC_Z 64
typedef struct {uint64_t low; unsigned short high;} floatx80;
typedef struct {unsigned fpus,fpstt,fpuc,cc_src; struct {floatx80 d;} fpregs[8]; struct {unsigned short float_exception_flags;} fp_status;} CPUX86State;
static void helper_fpop(CPUX86State *e) {e->fpstt=(e->fpstt+1)&7;}

static void ft_x87_helper_compare_reg(CPUX86State *env,int index,int mode) {
    assert(index==7 && mode==5); env->fpus=(env->fpus ^ 0x55aa) & ~512u;
}
''' + wrapper + '''
int main(void) {for(unsigned sw=0;sw<65536;sw++) {
    CPUX86State env={.fpus=sw}; ft_x87_helper_compare_reg_fast(&env,7,5);
    assert(env.fpus==(((sw^0x55aa)&~512u)|(sw&512u)));
}
floatx80 q={UINT64_C(0xc000000000000001),0x7fff};
floatx80 sn={UINT64_C(0x8000000000000001),0x7fff};
floatx80 bad={1,0x3fff};
floatx80 one={UINT64_C(0x8000000000000000),0x3fff};
for(int quiet=0;quiet<2;quiet++)for(int mask=0;mask<2;mask++) {
    CPUX86State e={.fpus=512,.fpuc=mask,.cc_src=0x890};
    assert(ft_x87_fast_unordered(&e,q,one,quiet,false));
    assert(e.fpus==(0x4700u | (quiet?0u:(mask?1u:0x8081u))));
    assert(e.fp_status.float_exception_flags==(quiet?0u:1u));
    e=(CPUX86State){.fpuc=mask};
    assert(ft_x87_fast_unordered(&e,q,sn,quiet,true));
    assert((e.cc_src&0x45)==0x45 && (e.fpus&1));
    e=(CPUX86State){.fpuc=mask};
    assert(ft_x87_fast_unordered(&e,q,bad,true,false));
    assert(e.fpus==0x4500); /* Legacy stops at the first NaN. */
    e=(CPUX86State){.fpuc=mask};
    assert(ft_x87_fast_unordered(&e,bad,q,true,false));
    assert(e.fpus==(mask?0x4501u:0xc581u));
}
CPUX86State e={.fpus=512,.fpuc=0x37f};
e.fpregs[0].d=q;e.fpregs[7].d=one;
ft_x87_helper_compare_reg_fast(&e,7,5);
assert(e.fpstt==2 && e.fpus==0x4700);
}
''')
    exe = Path(td) / 'test'
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O2',str(p),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
