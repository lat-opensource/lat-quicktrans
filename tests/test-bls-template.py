#!/usr/bin/env python3
"""Interpret the actual BLS emitter and CF/ZF helpers; memory load is modeled."""
import os,subprocess,tempfile,sys
from pathlib import Path
R=Path(__file__).resolve().parents[1];s=(R/'src/emitter/fast_translator/emit-bit.inc.c').read_text()
def section(a,b):return s[s.index(a):s.index(b)]
body=section('static void ft_count_bits_set_zf_from_zero','static void ft_emit_popcnt_value')+section('static void ft_bls_set_cf_from_nonzero','static int ft_emit_bextr_template')
head=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
enum {FT_BLS_R32_RM,FT_BLS_R64_RM,GPR_NUM=16,la_t0=16,la_t2=18,la_t3=19,la_t4=20,la_zero=31,CF_USEDEF_BIT=1,ZF_USEDEF_BIT=64,SF_USEDEF_BIT=128,OF_USEDEF_BIT=2048};
typedef struct {int kind,reg,src,modrm;bool skip_flags,rex;} FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
typedef struct{int op,d,s,t,h,l;}Ins;static Ins ins[64];static int n;static uint64_t r[32],flags,mem;
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
#define ft_gpr(d) (d)
#define ft_rex_w(f) ((f)->rex)
static bool load(uint32_t **o,const FastTemplateFields*f,int*s,int w){if((f->modrm>>6)==3)*s=f->src;else{E(o,15,la_t0,0,0,w,0);*s=la_t0;}return true;}
#define ft_emit_load_rm64(o,f,p,s) load(o,f,s,64)
#define ft_emit_load_rm32(o,f,p,s) load(o,f,s,32)
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
case 15:r[x.d]=x.h==64?mem:(uint64_t)(int64_t)(int32_t)mem;break;default:assert(0);}}}
int main(void){unsigned cases=0;uint64_t seed=0x1234abcdefULL;
for(int w=32;w<=64;w+=32)for(int ext=1;ext<=3;ext++)for(int memory=0;memory<2;memory++)for(int alias=0;alias<2;alias++)for(int dead=0;dead<2;dead++)for(int dst=0;dst<=8;dst+=8)for(int j=0;j<80;j++){
seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint64_t v=j==0?0:j==1?UINT64_MAX:j<66?1ULL<<(j-2):j==66?0xdeadbeef00000000ULL:seed;
for(int k=0;k<32;k++)r[k]=seed;r[31]=0;int sr=alias?dst:dst==0?8:0;r[sr]=v;mem=v;flags=0x8d5;
FastTemplateFields f={.kind=w==64?FT_BLS_R64_RM:FT_BLS_R32_RM,.reg=dst,.src=sr,.modrm=(memory?0:192)|(ext<<3),.skip_flags=dead,.rex=w==64};
uint32_t c[64];n=0;int count=ft_emit_bls_template(&f,0,0,c);assert(count>0);
int want_count=memory+(w==32?2:(!memory&&alias))+(ext==3?3:2)+(!dead?(ext==2?7:10):0);
if(ext==3)want_count--;
if(EXPECT_OPT && dead && (w==32||(!memory&&alias)))want_count--;
assert(count==want_count);uint64_t src=w==32?(uint32_t)v:v;uint64_t z=ext==1?src&(src-1):ext==2?src^(src-1):src&(-src);if(w==32)z=(uint32_t)z;run(c,count);assert(r[dst]==z);
uint64_t want=(ext==3?(src!=0):(src==0))|((ext!=2&&z==0)?64:0)|(((z>>(w-1))&1)<<7);assert(dead?flags==0x8d5:(flags&0x8c1)==want);cases++;}
printf("actual BLS body %u cases PASS LATS=%d; load modeled; not full engine\n",cases,EXPECT_LATS);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'body.c').write_text(head+body+tail)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LATS=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('user',['-DEXPECT_LATS=0'])]:
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-DEXPECT_OPT='+str(int('--optimized' in sys.argv and label!='user')),*([] if os.environ.get('NO_SANITIZE') else ['-fsanitize=undefined']),*defs,str(p/'body.c'),'-o',str(p/label)],check=True);subprocess.run([str(p/label)],check=True)
