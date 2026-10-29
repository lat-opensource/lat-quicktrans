#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-misc.inc.c').read_text();s=s[s.index('static int ft_emit_latu_bound'):s.index('\n#endif\n\nstatic int ft_emit_nop_template')]
h=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t target_ulong;
typedef struct {int prefix2,modrm_mod,src,addr,offset;} FastTemplateFields;
typedef struct {int at;} FastBranchLabel;
typedef struct {int at;FastBranchLabel *label;} FastBranchFixup;
enum {dt_X86_PREFIX_OPSIZE=102,GPR_NUM=16,FT_BRANCH_BLT=7,FT_BRANCH_BGE=8,EXCP05_BOUND=5};
typedef struct {int op,d,a,b;} Insn; static Insn ir[64];static uint32_t *base;
static int ft_modrm_reg_index(const FastTemplateFields*f){return f->src;}
static int ft_gpr(int n){return n;}
static int ft_scratch_avoid3(int a,int b,int c){for(int n=20;n>=16;n--)if(n!=a&&n!=b&&n!=c)return n;assert(0);return 0;}
static bool ft_emit_rip_or_mem_addr(uint32_t**o,const FastTemplateFields*f,target_ulong pc,int*a){*a=f->addr;return true;}
static int ft_mem_access_offset(const FastTemplateFields*f,int a){return f->offset;}
static void emit(uint32_t**o,int op,int d,int a,int b){int n=*o-base;ir[n]=(Insn){op,d,a,b};*(*o)++=0;}
#define FT_LA_ADDI_D_EMIT(o,d,a,b) emit(o,1,d,a,b)
#define FT_LA_EXT_W_H_EMIT(o,d,a) emit(o,2,d,a,0)
#define FT_LA_SLLI_D_EMIT(o,d,a,b) emit(o,3,d,a,b)
#define FT_LA_SRAI_D_EMIT(o,d,a,b) emit(o,4,d,a,b)
#define FT_LA_LD_H_EMIT(o,d,a,b) emit(o,5,d,a,b)
#define FT_LA_LD_W_EMIT(o,d,a,b) emit(o,6,d,a,b)
static void ft_emit_branch_placeholder(uint32_t**o,FastBranchFixup*f,int op,int a,int b,FastBranchLabel*l){f->at=*o-base;f->label=l;emit(o,op,0,a,b);}
static void ft_bind_branch_label(FastBranchLabel*l,uint32_t*o){l->at=o-base;}
static void ft_resolve_branch_fixup(FastBranchFixup*f){ir[f->at].d=f->label->at;}
static void ft_emit_raise_exception(uint32_t**o,target_ulong pc,int e){assert(e==5);emit(o,9,0,0,0);}
'''
t=r'''
int main(void){uint32_t code[64];uint64_t r[32],saved[16];int64_t vals[]={INT32_MIN,-32769,-32768,-6,-5,0,5,6,32767,32768,INT32_MAX};unsigned count=0;
for(int width=16;width<=32;width+=16)for(int src=0;src<16;src++)for(int addr=16;addr<=20;addr++)for(int off=-16;off<=16;off+=16)for(int v=0;v<11;v++)for(int pair=0;pair<3;pair++){
int64_t lo=pair==0?-5:pair==1?5:(width==16?INT16_MIN:INT32_MIN),hi=pair==0?5:pair==1?-5:(width==16?INT16_MAX:INT32_MAX);
int64_t value=width==16?(int16_t)vals[v]:(int32_t)vals[v];
for(int j=0;j<32;j++)r[j]=0x1234567800000000ULL+j;r[src]=(uint64_t)vals[v];memcpy(saved,r,sizeof saved);r[addr]=1024-off;
FastTemplateFields f={width==16?102:0,0,src,addr,off};base=code;int n=ft_emit_latu_bound(&f,0x1234,code),fault=0,loads=0;assert(n>1);
for(int ip=0;ip<n;){Insn x=ir[ip++];switch(x.op){case 1:r[x.d]=r[x.a]+x.b;break;case 2:r[x.d]=(int16_t)r[x.a];break;case 3:r[x.d]=r[x.a]<<x.b;break;case 4:r[x.d]=(int64_t)r[x.a]>>x.b;break;case 5:case 6:{uint64_t a=r[x.a]+x.b;assert(a==1024||a==1024+width/8);assert(x.op==(width==16?5:6));r[x.d]=a==1024?lo:hi;loads++;break;}case 7:if((int64_t)r[x.a]<(int64_t)r[x.b])ip=x.d;break;case 8:if((int64_t)r[x.a]>=(int64_t)r[x.b])ip=x.d;break;case 9:fault=1;ip=n;break;default:assert(0);}}
assert(loads==2);assert(fault==(value<lo||value>hi));assert(!memcmp(saved,r,sizeof saved));count++;
}printf("BOUND emitter: %u cases passed\n",count);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'t.c').write_text(h+s+t)
 subprocess.run(['cc','-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p/'t.c'),'-o',str(p/'t')],check=True)
 subprocess.run([str(p/'t')],check=True)
