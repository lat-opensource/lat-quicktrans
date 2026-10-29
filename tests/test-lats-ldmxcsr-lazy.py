#!/usr/bin/env python3
"""Execute the LDMXCSR emitter's branch graph against legacy lazy policy."""
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'src/emitter/fast_translator/emit-helper.inc.c').read_text()
case = source.split('    case FT_HELPER_LDMXCSR:\n', 1)[1].split(
    '    case FT_HELPER_FXSAVE:', 1)[0]
start = source.index('static void ft_emit_lats_mxcsr_load(')
end = source.index('\n}', source.index('static void ft_emit_lats_mxcsr_hflags(')) + 2
hflags = source[start:end]
header = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define CONFIG_SOFTMMU 1
typedef struct { uint32_t mxcsr, old_mxcsr, hflags; } CPUX86State;
typedef struct { int modrm_mod, modrm_reg; } FastTemplateFields;
enum { la_zero, la_t0, la_t1, la_t2, la_t4, la_s0 };
enum { LOAD_INPUT, LOAD_ENV, STORE_ENV, PICK, XORI, ANDI, SLTU, INSERT,
       FT_BRANCH_BNE, FT_BRANCH_BEQ, FCSR, STATUS };
enum { FT_LA_OPCODE_LD_WU, FT_LA_OPCODE_ST_W, HF_SIGFPE_ON=10 };
typedef struct { int op, d, s, a, b; } Op;
static Op ops[100];
static uint32_t code[100], regs[8];
static int option_lazy_mxcsr, option_soft_fpu;
static CPUX86State env;
static int fcsr_writes, status_writes, env_writes, generic_env_accesses;
typedef struct { uint32_t *pc; } FastBranchLabel;
typedef struct { int pos; FastBranchLabel *label; } FastBranchFixup;
static void emit(uint32_t **out,int op,int d,int s,int a,int b) {
    ops[*out-code]=(Op){op,d,s,a,b}; ++*out;
}
#define lsenv_offset_of_mxcsr(x) offsetof(CPUX86State,mxcsr)
#define FT_LA_LD_WU_EMIT(o,d,s,a) emit(o,(s)==la_s0?LOAD_ENV:LOAD_INPUT,d,0,a,0)
#define FT_LA_ST_W_EMIT(o,d,s,a) emit(o,STORE_ENV,0,d,a,0)
static bool ft_offset_fits_imm12(int offset) { return offset>=-2048 && offset<=2047; }
#define FT_LA_BSTRPICK_W_EMIT(o,d,s,h,l) emit(o,PICK,d,s,h,l)
#define FT_LA_XORI_EMIT(o,d,s,i) emit(o,XORI,d,s,i,0)
#define FT_LA_ANDI_EMIT(o,d,s,i) emit(o,ANDI,d,s,i,0)
#define FT_LA_SLTU_EMIT(o,d,s,t) emit(o,SLTU,d,s,t,0)
#define FT_LA_BSTRINS_W_EMIT(o,d,s,h,l) emit(o,INSERT,d,s,h,l)
#define ft_mem_access_offset(f,a) 0
static bool ft_emit_rip_or_mem_addr(uint32_t **out,const FastTemplateFields *f,
                                   int pc,int *addr) { *addr=la_t4;return true; }
static void ft_emit_load_env(uint32_t **out,int d,int offset,int kind) {
    generic_env_accesses++;emit(out,LOAD_ENV,d,0,offset,0);
}
static void ft_emit_store_env(uint32_t **out,int s,int offset,int kind) {
    generic_env_accesses++;emit(out,STORE_ENV,0,s,offset,0);
}
static void ft_emit_branch_placeholder(uint32_t **out,FastBranchFixup *fix,
    int kind,int lhs,int rhs,FastBranchLabel *label) {
    fix->pos=*out-code;fix->label=label;emit(out,kind,lhs,rhs,0,0);
}
static void ft_bind_branch_label(FastBranchLabel *label,uint32_t *out) { label->pc=out; }
static void ft_resolve_branch_fixup(FastBranchFixup *fix) { ops[fix->pos].a=fix->label->pc-code; }
static void ft_emit_fcsr_from_mxcsr(uint32_t **out,int r) { emit(out,FCSR,0,r,0,0); }
static void ft_emit_lats_mxcsr_status(uint32_t **out,int r) { emit(out,STATUS,0,r,0,0); }
'''
main = r'''
static int build(void) {
    uint32_t *out=code;FastTemplateFields storage={0,2},*fields=&storage;int pc=0;
    generic_env_accesses=0;
    do CASE while(0);
    assert(generic_env_accesses==0);
    return out-code;
}
static void execute(int count,uint32_t input) {
    for(int i=0;i<8;i++)regs[i]=0;
    fcsr_writes=status_writes=env_writes=0;
    for(int pc=0;pc<count;pc++) {
        Op x=ops[pc];uint32_t mask;
        switch(x.op) {
        case LOAD_INPUT:regs[x.d]=input;break;
        case LOAD_ENV:regs[x.d]=*(uint32_t*)((char*)&env+x.a);break;
        case STORE_ENV:*(uint32_t*)((char*)&env+x.a)=regs[x.s];env_writes++;break;
        case PICK:regs[x.d]=(regs[x.s]>>x.b)&((1u<<(x.a-x.b+1))-1);break;
        case XORI:regs[x.d]=regs[x.s]^x.a;break;
        case ANDI:regs[x.d]=regs[x.s]&x.a;break;
        case SLTU:regs[x.d]=regs[x.s]<regs[x.a];break;
        case INSERT:mask=((1u<<(x.a-x.b+1))-1)<<x.b;
            regs[x.d]=(regs[x.d]&~mask)|((regs[x.s]<<x.b)&mask);break;
        case FT_BRANCH_BNE:if(regs[x.d]!=regs[x.s])pc=x.a-1;break;
        case FT_BRANCH_BEQ:if(regs[x.d]==regs[x.s])pc=x.a-1;break;
        case FCSR:fcsr_writes++;break;
        case STATUS:status_writes++;break;
        default:assert(0);
        }
    }
}
int main(void) {
    uint32_t *out=code;
    ft_emit_lats_mxcsr_load(&out,la_t1,2048);
    ft_emit_lats_mxcsr_store(&out,la_t1,-2049);
    assert(generic_env_accesses==2);
    for(int soft=0;soft<2;soft++)for(int lazy=0;lazy<2;lazy++) {
        option_soft_fpu=soft;option_lazy_mxcsr=lazy;int count=build();
        for(uint32_t input=0;input<65536;input++)for(int mode=0;mode<4;mode++) {
            /* same; both changed; only current changed; only cache changed */
            env=(CPUX86State){input^((mode==1||mode==2)?0x2000:0),input^((mode==1||mode==3)?0x2000:0),0xa5a55a5a};
            uint32_t flags=env.hflags;bool hit=lazy&&mode==0;
            execute(count,input);
            assert(env.mxcsr==input);
            assert(fcsr_writes==!hit);
            assert(status_writes==!soft);
            if(soft&&!hit) {
                bool enabled=(((input>>7)^0x3f)&0x3d)!=0;
                flags=(flags&~(1u<<HF_SIGFPE_ON))|(enabled<<HF_SIGFPE_ON);
            }
            assert(env.hflags==flags);
            if(soft&&hit)assert(env_writes==0);
            if(lazy)assert(env.old_mxcsr==input);
        }
    }
    puts("LDMXCSR: 1048576 emitted-branch/state cases PASS");
}
'''.replace('CASE', case)
with tempfile.TemporaryDirectory() as directory:
    c = Path(directory) / 'test.c'
    c.write_text(header + hflags + main)
    exe = Path(directory) / 'test'
    subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-Wall', '-Werror',
                    str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
