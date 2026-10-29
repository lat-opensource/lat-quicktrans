#!/usr/bin/env python3
"""Interpret the actual BLS emitter and CF/ZF helpers; memory load is modeled."""
import os,subprocess,tempfile
from pathlib import Path
import sys
args=[x for x in sys.argv[1:] if not x.startswith('--')]
R=Path(args[0]) if args else Path(__file__).resolve().parents[1];s=(R/'src/emitter/fast_translator/emit-bit.inc.c').read_text()
def section(a,b):return s[s.index(a):s.index(b)]
body=section('static int ft_count_bits_width','static int ft_emit_andn_template')
head=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
enum {FT_LZCNT_R16_RM16,FT_LZCNT_R32_RM32,FT_LZCNT_R64_RM64,FT_TZCNT_R16_RM16,FT_TZCNT_R32_RM32,FT_TZCNT_R64_RM64,FT_POPCNT_R16_RM16,FT_POPCNT_R32_RM32,FT_POPCNT_R64_RM64,dt_X86_PREFIX_OPSIZE=102,la_t1=17,PF_USEDEF_BIT=4,AF_USEDEF_BIT=16,GPR_NUM=16,la_t0=16,la_t2=18,la_t3=19,la_t4=20,la_zero=31,CF_USEDEF_BIT=1,ZF_USEDEF_BIT=64,SF_USEDEF_BIT=128,OF_USEDEF_BIT=2048};
typedef int FastTemplateKind;
typedef struct {int kind,reg,src,modrm,prefix2;bool skip_flags,rex;} FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
typedef struct{int op,d,s,t,h,l;}Ins;static Ins ins[128];static int n;static uint64_t r[32],flags,mem;
static uint32_t add(int op,int d,int s,int t,int h,int l){ins[n]=(Ins){op,d,s,t,h,l};return n++;}
#define E(o,op,d,s,t,h,l) do{*(*(o))++=add(op,d,s,t,h,l);}while(0)
#define FT_LA_OR_EMIT(o,d,s,t) E(o,1,d,s,t,0,0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) E(o,2,d,s,0,h,l)
#define FT_LA_ADDI_D_EMIT(o,d,s,i) E(o,3,d,s,0,i,0)
#define FT_LA_ADDI_W_EMIT(o,d,s,i) E(o,4,d,s,0,i,0)
#define FT_LA_AND_EMIT(o,d,s,t) E(o,5,d,s,t,0,0)
#define FT_LA_XOR_EMIT(o,d,s,t) E(o,6,d,s,t,0,0)
#define FT_LA_SUB_D_EMIT(o,d,s,t) E(o,7,d,s,t,0,0)
#define FT_LA_SUB_W_EMIT(o,d,s,t) E(o,8,d,s,t,0,0)
#define FT_LA_BEQ_EMIT(o,s,t,k) E(o,9,0,s,t,k,0)
#define FT_LA_BNE_EMIT(o,s,t,k) E(o,10,0,s,t,k,0)
#define FT_LA_ORI_EMIT(o,d,s,k) E(o,11,d,s,0,k,0)
#define FT_LA_X86MTFLAG_EMIT(o,s,m) E(o,12,0,s,0,m,0)
#define FT_LA_SRLI_D_EMIT(o,d,s,k) E(o,13,d,s,0,k,0)
#define FT_LA_SLLI_D_EMIT(o,d,s,k) E(o,14,d,s,0,k,0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) E(o,16,d,s,0,h,l)
#define FT_LA_CLZ_D_EMIT(o,d,s) E(o,17,d,s,0,0,0)
#define FT_LA_CTZ_D_EMIT(o,d,s) E(o,18,d,s,0,0,0)
#define FT_LA_SUB_D_EMIT_UNUSED 0
#define FT_LA_ADD_D_EMIT(o,d,s,t) E(o,19,d,s,t,0,0)
#define FT_LA_ANDI_EMIT(o,d,s,k) E(o,20,d,s,0,k,0)
static void ft_emit_li64(uint32_t**o,int d,uint64_t v){E(o,21,d,0,0,(int)(v>>32),(int)v);}
#define ft_modrm_reg_index(f) ((f)->reg)
#define ft_gpr(d) (d)
#define ft_rex_w(f) ((f)->rex)
static bool load(uint32_t **o,const FastTemplateFields*f,int*s,int w){if((f->modrm>>6)==3)*s=f->src;else{E(o,15,la_t0,0,0,w,0);*s=la_t0;}return true;}
#define ft_emit_load_rm64(o,f,p,s) load(o,f,s,64)
#define ft_emit_load_rm32(o,f,p,s) load(o,f,s,32)
#define ft_emit_load_rm16(o,f,p,s) load(o,f,s,16)
'''
tail=r'''
static void run(uint32_t*c,int count){for(int ip=0;ip<count;ip++){Ins x=ins[c[ip]];switch(x.op){
case 1:r[x.d]=r[x.s]|r[x.t];break;case 2:r[x.d]=(r[x.s]&((1ULL<<(x.h+1))-1))>>x.l;break;
case 3:r[x.d]=r[x.s]+x.h;break;case 4:r[x.d]=(uint64_t)(int64_t)(int32_t)(r[x.s]+x.h);break;
case 5:r[x.d]=r[x.s]&r[x.t];break;case 6:r[x.d]=r[x.s]^r[x.t];break;case 7:r[x.d]=r[x.s]-r[x.t];break;
case 8:r[x.d]=(uint64_t)(int64_t)(int32_t)(r[x.s]-r[x.t]);break;
case 9:if(r[x.s]==r[x.t])ip+=x.h-1;break;case 10:if(r[x.s]!=r[x.t])ip+=x.h-1;break;
case 11:r[x.d]=r[x.s]|x.h;break;case 12:flags=(flags&~(uint64_t)x.h)|(r[x.s]&x.h);break;
case 13:r[x.d]=r[x.s]>>x.h;break;case 14:r[x.d]=r[x.s]<<x.h;break;
case 15:r[x.d]=x.h==64?mem:x.h==32?(uint64_t)(int64_t)(int32_t)mem:(uint64_t)(int64_t)(int16_t)mem;break;
case 16:r[x.d]=(r[x.d]&~0xffffULL)|(r[x.s]&0xffff);break;
case 17:r[x.d]=r[x.s]?__builtin_clzll(r[x.s]):64;break;
case 18:r[x.d]=r[x.s]?__builtin_ctzll(r[x.s]):64;break;
case 19:r[x.d]=r[x.s]+r[x.t];break;
case 20:r[x.d]=r[x.s]&x.h;break;
case 21:r[x.d]=((uint64_t)(uint32_t)x.h<<32)|(uint32_t)x.l;break;default:assert(0);}}}
int main(void){unsigned cases=0;uint64_t seed=0x1234abcdefULL;
for(int wi=0;wi<3;wi++)for(int op=0;op<3;op++)for(int memory=0;memory<2;memory++)for(int alias=0;alias<2;alias++)for(int dead=0;dead<2;dead++)for(int dst=0;dst<=8;dst+=8)for(int j=0;j<80;j++){
int w=wi==0?16:wi==1?32:64;seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint64_t v=j==0?0:j==1?UINT64_MAX:j<66?1ULL<<(j-2):j==66?0xdeadbeef00000000ULL:seed;
for(int k=0;k<32;k++)r[k]=seed;r[31]=0;int sr=alias?dst:dst==0?8:0;r[sr]=v;uint64_t old=r[dst];mem=v;flags=0x8d5;
FastTemplateFields f={.kind=op*3+wi,.reg=dst,.src=sr,.modrm=(memory?0:192),.skip_flags=dead,.rex=w==64,.prefix2=w==16?dt_X86_PREFIX_OPSIZE:0};
uint32_t c[128];n=0;int count=ft_emit_count_bits_template(&f,0,0,c);assert(count>0);uint64_t src=w==64?v:v&((1ULL<<w)-1);uint64_t z=op==0?(src?__builtin_clzll(src)-(64-w):w):op==1?(src?__builtin_ctzll(src):w):__builtin_popcountll(src);uint64_t wantdst=w==16?(old&~0xffffULL)|z:z;run(c,count);assert(r[dst]==wantdst);if(w==32)assert((r[dst]>>32)==0);
if(EXPECT_OPT && EXPECT_LOCAL && dead && w!=16){int last=ins[c[count-1]].op;assert(last==(op==2?20:op==0?(w==64?17:3):(w==64?18:11)));}else assert(ins[c[count-1]].op==(w==64?1:w==32?2:16));
uint64_t want=op==2?(src==0?64:0):(src==0)|(z==0?64:0);assert(dead?flags==0x8d5:(flags&(op==2?0x8d5:0x41))==want);cases++;}
printf("actual count-bits body %u cases PASS local-sequence=%d; load modeled; not full engine\n",cases,EXPECT_LOCAL);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'body.c').write_text(head+body+tail)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LOCAL=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('user',['-DEXPECT_LOCAL=0'])]:
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-DEXPECT_OPT='+str(int('--optimized' in sys.argv)),*([] if os.environ.get('NO_SANITIZE') else ['-fsanitize=undefined']),*defs,str(p/'body.c'),'-o',str(p/label)],check=True);subprocess.run([str(p/label)],check=True)
